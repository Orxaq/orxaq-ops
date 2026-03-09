import Foundation

public protocol VerificationRunner {
    func run(command: [String], sourcePath: String, targetPath: String) throws -> VerificationOutcome
}

public struct ProcessVerificationRunner: VerificationRunner {
    public var timeout: TimeInterval

    public init(timeout: TimeInterval = 10) {
        self.timeout = timeout
    }

    public func run(command: [String], sourcePath: String, targetPath: String) throws -> VerificationOutcome {
        guard let executable = command.first else {
            throw CassPolicyError.verifierExecutionFailed("Verifier command is empty.")
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = Array(command.dropFirst()) + [sourcePath]
        var environment = ProcessInfo.processInfo.environment.merging(
            [
                "CASS_SOURCE_PATH": sourcePath,
                "CASS_TARGET_PATH": targetPath,
            ],
            uniquingKeysWith: { _, new in new }
        )
        if let projectDirectory = inferProjectDirectory(for: executable, targetPath: targetPath) {
            environment["CLAUDE_PROJECT_DIR"] = projectDirectory
        }
        process.environment = environment

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        let stdinPipe = Pipe()
        process.standardInput = stdinPipe

        let semaphore = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in
            semaphore.signal()
        }

        do {
            try process.run()
            let payload = verifierInputJSON(sourcePath: sourcePath, targetPath: targetPath)
            stdinPipe.fileHandleForWriting.write(payload)
            try stdinPipe.fileHandleForWriting.close()
        } catch {
            throw CassPolicyError.verifierExecutionFailed("Unable to launch verifier: \(error.localizedDescription)")
        }

        if semaphore.wait(timeout: .now() + timeout) == .timedOut {
            process.terminate()
            return .infrastructureFailure(detail: "Verifier timed out after \(Int(timeout))s.")
        }

        let stdout = String(data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let detail = [stdout, stderr]
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: "\n")

        switch process.terminationStatus {
        case 0:
            return .allow(detail: detail)
        case 2:
            return .deny(detail: detail)
        default:
            return .infrastructureFailure(
                detail: detail.isEmpty
                    ? "Verifier exited with status \(process.terminationStatus)."
                    : "Verifier exited with status \(process.terminationStatus).\n\(detail)"
            )
        }
    }

    private func verifierInputJSON(sourcePath: String, targetPath: String) -> Data {
        let payload: [String: Any] = [
            "tool_name": "Promote",
            "tool_input": [
                "file_path": targetPath,
                "candidate_path": sourcePath,
                "target_path": targetPath,
            ],
        ]
        return (try? JSONSerialization.data(withJSONObject: payload)) ?? Data()
    }

    private func inferProjectDirectory(for executable: String, targetPath: String) -> String? {
        let normalizedExecutable = URL(fileURLWithPath: executable).standardized.path
        let hookMarker = "/.claude/hooks/"
        if let range = normalizedExecutable.range(of: hookMarker) {
            return String(normalizedExecutable[..<range.lowerBound])
        }

        var candidateURL = URL(fileURLWithPath: targetPath).standardized.deletingLastPathComponent()
        let fileManager = FileManager.default
        while candidateURL.path != "/" {
            let claudePath = candidateURL.appendingPathComponent(".claude").path
            let gitPath = candidateURL.appendingPathComponent(".git").path
            if fileManager.fileExists(atPath: claudePath) || fileManager.fileExists(atPath: gitPath) {
                return candidateURL.path
            }
            candidateURL.deleteLastPathComponent()
        }
        return nil
    }
}

public struct PolicyEngine {
    public let policy: PolicyDocument
    private let nowProvider: () -> Date

    public init(policy: PolicyDocument, nowProvider: @escaping () -> Date = Date.init) {
        self.policy = policy.normalized()
        self.nowProvider = nowProvider
    }

    public func decide(
        event: RuntimeEvent,
        verifier: VerificationRunner? = nil,
        activeLeases: [BreakglassLease] = []
    ) throws -> PolicyDecision {
        let leases = activeLeases
            .filter { $0.profile == policy.profile && $0.isActive(at: nowProvider()) }

        if let commandDecision = try commandDecision(for: event, activeLeases: leases) {
            return commandDecision
        }

        if let pathDecision = try pathDecision(for: event, verifier: verifier, activeLeases: leases) {
            return pathDecision
        }

        if let targetPath = event.targetPath,
           policy.writableReferencePaths.contains(where: { PathMatcher.matches(glob: $0, path: targetPath) }) {
            return PolicyDecision(
                action: .allow,
                reason: "Path is explicitly outside the governed control plane.",
                detail: targetPath
            )
        }

        return PolicyDecision(action: .allow, reason: "No matching policy rule.")
    }

    private func commandDecision(
        for event: RuntimeEvent,
        activeLeases: [BreakglassLease]
    ) throws -> PolicyDecision? {
        guard event.operation == .exec, let argv = event.argv, !argv.isEmpty else {
            return nil
        }

        let joined = argv.joined(separator: " ")
        for rule in policy.governedCommands {
            let regex = try NSRegularExpression(pattern: rule.commandRegex)
            let range = NSRange(location: 0, length: joined.utf16.count)
            guard regex.firstMatch(in: joined, options: [], range: range) != nil else {
                continue
            }

            if let lease = matchingLease(for: event, within: activeLeases) {
                return PolicyDecision(
                    action: .allow,
                    reason: "Breakglass lease overrides governed command denial.",
                    matchedRuleID: rule.id,
                    matchedLeaseID: lease.leaseID,
                    detail: joined
                )
            }

            return PolicyDecision(
                action: rule.action,
                reason: rule.reason,
                matchedRuleID: rule.id,
                detail: joined
            )
        }

        return nil
    }

    private func pathDecision(
        for event: RuntimeEvent,
        verifier: VerificationRunner?,
        activeLeases: [BreakglassLease]
    ) throws -> PolicyDecision? {
        if let targetPath = event.targetPath,
           let rule = policy.governedPaths.first(where: { $0.operations.contains(event.operation) && PathMatcher.matches(glob: $0.pathPattern, path: targetPath) }) {
            if let lease = matchingLease(for: event, within: activeLeases) {
                return PolicyDecision(
                    action: .allow,
                    reason: "Breakglass lease overrides governed path denial.",
                    matchedRuleID: rule.id,
                    matchedLeaseID: lease.leaseID,
                    detail: targetPath
                )
            }

            return PolicyDecision(
                action: rule.action,
                reason: rule.reason,
                matchedRuleID: rule.id,
                detail: targetPath
            )
        }

        return try verificationDecision(for: event, verifier: verifier, activeLeases: activeLeases)
    }

    private func verificationDecision(
        for event: RuntimeEvent,
        verifier: VerificationRunner?,
        activeLeases: [BreakglassLease]
    ) throws -> PolicyDecision? {
        guard let targetPath = event.targetPath else {
            return nil
        }

        for rule in policy.verificationRules {
            let regex = try NSRegularExpression(pattern: rule.targetPathRegex)
            let range = NSRange(location: 0, length: targetPath.utf16.count)
            guard regex.firstMatch(in: targetPath, options: [], range: range) != nil else {
                continue
            }

            let lease = matchingLease(for: event, within: activeLeases)

            switch event.operation {
            case .rename, .copyFile, .clone, .exchangeData:
                guard let sourcePath = event.sourcePath else {
                    return PolicyDecision(
                        action: .deny,
                        reason: "\(rule.reason) Source path missing for verification.",
                        matchedRuleID: rule.id,
                        matchedLeaseID: lease?.leaseID,
                        detail: targetPath
                    )
                }
                guard let verifier else {
                    return PolicyDecision(
                        action: .deny,
                        reason: "\(rule.reason) Verifier is unavailable.",
                        matchedRuleID: rule.id,
                        matchedLeaseID: lease?.leaseID,
                        detail: sourcePath
                    )
                }

                let result = try verifier.run(command: rule.verifierCommand, sourcePath: sourcePath, targetPath: targetPath)
                switch result {
                case .allow(let detail):
                    return PolicyDecision(
                        action: .allow,
                        reason: "Verification passed for governed Python promotion.",
                        matchedRuleID: rule.id,
                        matchedLeaseID: lease?.leaseID,
                        detail: detail.isEmpty ? sourcePath : detail
                    )

                case .deny(let detail):
                    if let lease, lease.bypassVerifier {
                        return PolicyDecision(
                            action: .allow,
                            reason: "Breakglass lease bypassed verifier denial for governed Python promotion.",
                            matchedRuleID: rule.id,
                            matchedLeaseID: lease.leaseID,
                            detail: detail.isEmpty ? sourcePath : detail,
                            verifierBypassed: true
                        )
                    }
                    return PolicyDecision(
                        action: .deny,
                        reason: "\(rule.reason) Verifier blocked promotion into the governed Python path.",
                        matchedRuleID: rule.id,
                        matchedLeaseID: lease?.leaseID,
                        detail: detail.isEmpty ? sourcePath : detail
                    )

                case .infrastructureFailure(let detail):
                    return PolicyDecision(
                        action: .deny,
                        reason: "\(rule.reason) Verifier infrastructure failed closed.",
                        matchedRuleID: rule.id,
                        matchedLeaseID: lease?.leaseID,
                        detail: detail
                    )
                }

            case .openWrite, .create, .truncate:
                if let lease = lease, lease.bypassVerifier {
                    return PolicyDecision(
                        action: .allow,
                        reason: "Breakglass lease bypassed direct-write verification gate.",
                        matchedRuleID: rule.id,
                        matchedLeaseID: lease.leaseID,
                        detail: targetPath,
                        verifierBypassed: true
                    )
                }

                return PolicyDecision(
                    action: .deny,
                    reason: "\(rule.reason) Direct in-place writes are denied; use a staged file and atomic promotion.",
                    matchedRuleID: rule.id,
                    matchedLeaseID: lease?.leaseID,
                    detail: targetPath
                )

            default:
                continue
            }
        }
        return nil
    }

    private func matchingLease(
        for event: RuntimeEvent,
        within leases: [BreakglassLease]
    ) -> BreakglassLease? {
        let candidates = leaseCandidates(for: event)
        let matching = leases.filter { lease in
            lease.operations.contains(event.operation) && lease.pathPatterns.contains(where: { pattern in
                pattern == "*"
                    || candidates.contains(where: { candidate in PathMatcher.matches(glob: pattern, path: candidate) })
            })
        }

        return matching.sorted(by: leasePrecedence).first
    }

    private func leaseCandidates(for event: RuntimeEvent) -> [String] {
        var candidates = [String]()
        if let targetPath = event.targetPath {
            candidates.append(targetPath)
        }
        if let sourcePath = event.sourcePath {
            candidates.append(sourcePath)
        }
        if let argv = event.argv {
            for argument in argv {
                if argument.hasPrefix("/") || argument.hasPrefix("~") || argument.hasPrefix(".") {
                    candidates.append(argument)
                }
                candidates.append(contentsOf: absolutePathFragments(in: argument))
            }
        }
        return Array(Set(candidates))
    }

    private func absolutePathFragments(in token: String) -> [String] {
        let pattern = #"/[^\s'"]+"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            return []
        }
        let range = NSRange(location: 0, length: token.utf16.count)
        return regex.matches(in: token, options: [], range: range).compactMap { match in
            Range(match.range, in: token).map { String(token[$0]) }
        }
    }

    private func leasePrecedence(_ lhs: BreakglassLease, _ rhs: BreakglassLease) -> Bool {
        let lhsScore = specificityScore(for: lhs)
        let rhsScore = specificityScore(for: rhs)
        if lhsScore != rhsScore {
            return lhsScore > rhsScore
        }
        if lhs.expiresAt != rhs.expiresAt {
            return lhs.expiresAt < rhs.expiresAt
        }
        if lhs.createdAt != rhs.createdAt {
            return lhs.createdAt < rhs.createdAt
        }
        return lhs.leaseID < rhs.leaseID
    }

    private func specificityScore(for lease: BreakglassLease) -> Int {
        lease.pathPatterns.map { pattern in
            pattern.filter { $0 != "*" && $0 != "?" }.count
        }.max() ?? 0
    }
}
