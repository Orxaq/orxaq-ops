import CassEndpointSecuritySupport
import CassPolicyCore
import Foundation

private struct PromotionReport: Encodable {
    var status: String
    var source: String
    var target: String
    var operation: String
    var reason: String
    var ruleID: String?
    var leaseID: String?
    var detail: String?
    var verifierBypassed: Bool?
}

enum CassCtlCLI {
    static func main() throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard let command = arguments.first else {
            throw CassPolicyError.invalidCommand("Expected subcommand: doctor, status, install-policy, promote, activate, deactivate, yubikey, policy, or lease")
        }

        switch command {
        case "doctor":
            try CLIHelpers.printJSON(try doctor(arguments))
        case "status":
            try CLIHelpers.printJSON(try status(arguments))
        case "install-policy":
            try CLIHelpers.printJSON(try installPolicy(arguments))
        case "promote":
            try promote(arguments)
        case "activate":
            try CLIHelpers.printJSON(try activate(arguments))
        case "deactivate":
            try CLIHelpers.printJSON(try deactivate(arguments))
        case "yubikey":
            try yubikey(arguments)
        case "policy":
            try policy(arguments)
        case "lease":
            try lease(arguments)
        default:
            throw CassPolicyError.invalidCommand(command)
        }
    }

    private static func doctor(_ arguments: [String]) throws -> DoctorReport {
        let layout = runtimeLayout(arguments)
        let deployment = deploymentConfig(arguments)
        let signedPolicyPath = CLIHelpers.optionalValue(after: "--signed-policy", in: arguments) ?? layout.activePolicyPath
        let identityCommonName = CLIHelpers.optionalValue(after: "--identity-common-name", in: arguments)
        let leaseStore = LeaseStore(layout: layout)
        let includeAppleChecks = CLIHelpers.hasFlag("--apple-es", in: arguments)

        var checks = [DoctorCheck]()
        checks.append(runtimeOwnershipCheck(layout: layout))
        if includeAppleChecks {
            checks.append(hostAppPresenceCheck(deployment: deployment))
            checks.append(appleTeamCheck(deployment: deployment))
            checks.append(managedEntitlementCheck(deployment: deployment))
            checks.append(provisioningAssetsCheck(deployment: deployment))
        }

        if let identityCommonName {
            checks.append(yubiKeyIdentityCheck(commonName: identityCommonName))
        } else {
            checks.append(anyYubiKeyIdentityCheck())
        }

        if FileManager.default.fileExists(atPath: signedPolicyPath) {
            do {
                let envelope = try PolicyLoader.loadSignedPolicy(at: signedPolicyPath)
                try PolicySigner.verify(envelope: envelope)
                checks.append(
                    DoctorCheck(
                        id: "signed-policy",
                        status: .pass,
                        summary: "Signed policy is present and valid.",
                        detail: signedPolicyPath
                    )
                )
                if includeAppleChecks {
                    let daemon = EndpointSecurityDaemon(
                        envelope: envelope,
                        layout: layout,
                        deploymentConfig: deployment
                    )
                    checks.append(contentsOf: daemon.doctor().checks.filter { $0.id != "signed-policy" })
                }
            } catch {
                checks.append(
                    DoctorCheck(
                        id: "signed-policy",
                        status: .fail,
                        summary: "Signed policy validation failed.",
                        detail: error.localizedDescription,
                        remediation: "Re-sign the active policy with the YubiKey identity and reinstall it into the runtime root."
                    )
                )
            }
        } else {
            checks.append(
                DoctorCheck(
                    id: "signed-policy",
                    status: .fail,
                    summary: "Active signed policy is missing.",
                    detail: signedPolicyPath,
                    remediation: "Run `cassctl install-policy --signed-policy <path>` to install a signed policy into the runtime root."
                )
            )
            if includeAppleChecks {
                checks.append(
                    DoctorCheck(
                        id: "endpoint-security-client",
                        status: .fail,
                        summary: "Endpoint Security probe was skipped because no signed policy is installed.",
                        remediation: "Install a signed policy first so the daemon probe can run against the real runtime state."
                    )
                )
            }
        }

        do {
            try leaseStore.validate()
            checks.append(
                DoctorCheck(
                    id: "lease-store",
                    status: .pass,
                    summary: "Lease store is valid."
                )
            )
        } catch {
            checks.append(
                DoctorCheck(
                    id: "lease-store",
                    status: .fail,
                    summary: "Lease store validation failed.",
                    detail: error.localizedDescription,
                    remediation: "Repair or remove invalid lease artifacts under the runtime lease directory."
                )
            )
        }

        let report = DoctorReport(
            generatedAt: CassTime.string(),
            overallStatus: checks.map(\.status).max() ?? .pass,
            runtimeRoot: layout.rootDirectory,
            hostAppPath: includeAppleChecks ? deployment.hostAppPath : "",
            checks: deduplicateChecks(checks)
        )
        try PolicyLoader.writeJSON(status(from: report, layout: layout), to: layout.statusPath)
        return report
    }

    private static func status(_ arguments: [String]) throws -> StatusReport {
        let layout = runtimeLayout(arguments)
        let deployment = deploymentConfig(arguments)
        let leaseStore = LeaseStore(layout: layout)
        let signedPolicyPath = CLIHelpers.optionalValue(after: "--signed-policy", in: arguments) ?? layout.activePolicyPath

        if FileManager.default.fileExists(atPath: layout.statusPath),
           let stored: StatusReport = try? PolicyLoader.loadJSON(StatusReport.self, at: layout.statusPath) {
            return try refreshedStatus(from: stored, layout: layout, deployment: deployment, signedPolicyPath: signedPolicyPath, leaseStore: leaseStore)
        }

        let checks = [
            runtimeOwnershipCheck(layout: layout),
        ]
        let activationState: ActivationState
        if FileManager.default.fileExists(atPath: layout.activationRequestPath) {
            activationState = .activationRequested
        } else if FileManager.default.fileExists(atPath: signedPolicyPath) {
            activationState = .policyInstalled
        } else {
            activationState = .inactive
        }
        let report = StatusReport(
            generatedAt: CassTime.string(),
            activationState: activationState,
            runtimeRoot: layout.rootDirectory,
            hostAppPath: deployment.hostAppPath,
            activeLeaseCount: (try? leaseStore.activeLeases().count) ?? 0,
            checks: deduplicateChecks(checks)
        )
        try PolicyLoader.writeJSON(report, to: layout.statusPath)
        return report
    }

    private static func installPolicy(_ arguments: [String]) throws -> StatusReport {
        let layout = runtimeLayout(arguments)
        let signedPolicyPath = try CLIHelpers.value(after: "--signed-policy", in: arguments)
        let envelope = try PolicyLoader.loadSignedPolicy(at: signedPolicyPath)
        try PolicySigner.verify(envelope: envelope)
        try RuntimeSupport.ensureRuntimeDirectories(layout: layout)
        try PolicyLoader.writeSignedPolicy(envelope, to: layout.activePolicyPath)

        let report = StatusReport(
            generatedAt: CassTime.string(),
            activationState: .policyInstalled,
            runtimeRoot: layout.rootDirectory,
            hostAppPath: CassDeploymentConfig.production.hostAppPath,
            signedPolicyPath: layout.activePolicyPath,
            loadedProfile: envelope.policy.profile,
            memoryControl: envelope.policy.memoryControl,
            policyFingerprint: try RuntimeSupport.fingerprint(for: envelope),
            activeLeaseCount: 0,
            checks: deduplicateChecks([
                runtimeOwnershipCheck(layout: layout),
                DoctorCheck(
                    id: "signed-policy",
                    status: .pass,
                    summary: "Signed policy installed into the runtime root.",
                    detail: layout.activePolicyPath
                ),
            ])
        )
        try PolicyLoader.writeJSON(report, to: layout.statusPath)
        return report
    }

    private static func activate(_ arguments: [String]) throws -> StatusReport {
        let layout = runtimeLayout(arguments)
        let deployment = deploymentConfig(arguments)
        let identityCommonName = try CLIHelpers.value(after: "--identity-common-name", in: arguments)
        let profileRaw = try CLIHelpers.value(after: "--profile", in: arguments)
        guard let profile = PolicyProfile(rawValue: profileRaw) else {
            throw CassPolicyError.invalidPolicy("Unknown profile '\(profileRaw)'.")
        }

        let identityReport = try PolicySigner.doctorIdentity(commonName: identityCommonName)
        guard identityReport.identity.isTokenBacked else {
            throw CassPolicyError.preflightFailed("Identity '\(identityCommonName)' is not token-backed. Phase 1 live activation requires a YubiKey/CTK-backed PIV identity.")
        }
        guard identityReport.signingChallengePassed else {
            throw CassPolicyError.preflightFailed("Identity '\(identityCommonName)' failed the signing challenge.")
        }

        try RuntimeSupport.ensureRuntimeDirectories(layout: layout)
        try ensureActivationPreflight(layout: layout, deployment: deployment, identityCommonName: identityCommonName)

        let home = CLIHelpers.optionalValue(after: "--home", in: arguments) ?? NSHomeDirectory()
        let repo = CLIHelpers.optionalValue(after: "--repo", in: arguments) ?? "\(home)/dev/orxaq"
        let verifier = CLIHelpers.optionalValue(after: "--verifier", in: arguments) ?? "\(repo)/.claude/hooks/cass_code_verify.sh"
        let memoryRaw = CLIHelpers.optionalValue(after: "--memory-control", in: arguments) ?? MemoryControlMode.disabled.rawValue
        guard let memoryControl = MemoryControlMode(rawValue: memoryRaw) else {
            throw CassPolicyError.invalidPolicy("Unknown memory control mode '\(memoryRaw)'.")
        }

        let policy = PolicyFactory.makeClaudeCodePolicy(
            homeDirectory: home,
            repoDirectory: repo,
            verifierPath: verifier,
            profile: profile,
            memoryControl: memoryControl
        )
        let material = try PolicySigner.loadIdentity(commonName: identityCommonName)
        let envelope = try PolicySigner.sign(policy: policy, using: material)
        try PolicySigner.verify(envelope: envelope)

        try PolicyLoader.writeSignedPolicy(envelope, to: layout.activePolicyPath)

        let request = ActivationRequest(
            requestedAt: CassTime.string(),
            profile: profile,
            signedPolicyPath: layout.activePolicyPath,
            runtimeRoot: layout.rootDirectory,
            hostAppBundleIdentifier: deployment.hostAppBundleIdentifier,
            systemExtensionBundleIdentifier: deployment.systemExtensionBundleIdentifier
        )
        try PolicyLoader.writeJSON(request, to: layout.activationRequestPath)

        let launched = try launchHostAppIfPresent(deployment: deployment, activationRequestPath: layout.activationRequestPath)
        let policyFingerprint = try RuntimeSupport.fingerprint(for: envelope)
        let status = StatusReport(
            generatedAt: CassTime.string(),
            activationState: launched ? .pendingApproval : .activationRequested,
            runtimeRoot: layout.rootDirectory,
            hostAppPath: deployment.hostAppPath,
            signedPolicyPath: layout.activePolicyPath,
            loadedProfile: envelope.policy.profile,
            memoryControl: envelope.policy.memoryControl,
            policyFingerprint: policyFingerprint,
            yubikeyIdentityCommonName: identityCommonName,
            activeLeaseCount: 0,
            checks: deduplicateChecks([
                runtimeOwnershipCheck(layout: layout),
                hostAppPresenceCheck(deployment: deployment),
                yubiKeyIdentityCheck(commonName: identityCommonName),
            ])
        )
        try PolicyLoader.writeJSON(status, to: layout.statusPath)
        return status
    }

    private static func deactivate(_ arguments: [String]) throws -> StatusReport {
        let layout = runtimeLayout(arguments)
        let deployment = deploymentConfig(arguments)
        let storedStatus = try? PolicyLoader.loadJSON(StatusReport.self, at: layout.statusPath)
        let profile = storedStatus?.loadedProfile ?? .strict
        let request = ActivationRequest(
            requestedAt: CassTime.string(),
            profile: profile,
            signedPolicyPath: layout.activePolicyPath,
            runtimeRoot: layout.rootDirectory,
            hostAppBundleIdentifier: deployment.hostAppBundleIdentifier,
            systemExtensionBundleIdentifier: deployment.systemExtensionBundleIdentifier
        )

        try PolicyLoader.writeJSON(request, to: layout.activationRequestPath)
        _ = try launchHostAppIfPresent(deployment: deployment, deactivationRequestPath: layout.activationRequestPath)

        let report = StatusReport(
            generatedAt: CassTime.string(),
            activationState: .deactivationRequested,
            runtimeRoot: layout.rootDirectory,
            hostAppPath: deployment.hostAppPath,
            signedPolicyPath: FileManager.default.fileExists(atPath: layout.activePolicyPath) ? layout.activePolicyPath : nil,
            checks: deduplicateChecks([
                runtimeOwnershipCheck(layout: layout),
                hostAppPresenceCheck(deployment: deployment),
            ])
        )
        try PolicyLoader.writeJSON(report, to: layout.statusPath)
        return report
    }

    private static func yubikey(_ arguments: [String]) throws {
        guard arguments.count >= 2 else {
            throw CassPolicyError.invalidCommand("Expected `cassctl yubikey list-identities` or `cassctl yubikey doctor`.")
        }
        switch arguments[1] {
        case "list-identities":
            let identities = try PolicySigner.listIdentities().filter(\.isTokenBacked)
            try CLIHelpers.printJSON(identities)
        case "doctor":
            let commonName = try CLIHelpers.value(after: "--identity-common-name", in: arguments)
            try CLIHelpers.printJSON(try PolicySigner.doctorIdentity(commonName: commonName))
        default:
            throw CassPolicyError.invalidCommand(arguments[1])
        }
    }

    private static func policy(_ arguments: [String]) throws {
        guard arguments.count >= 2 else {
            throw CassPolicyError.invalidCommand("Expected `cassctl policy sign`.")
        }
        switch arguments[1] {
        case "sign":
            let policyPath = try CLIHelpers.value(after: "--policy", in: arguments)
            let outputPath = try CLIHelpers.value(after: "--output", in: arguments)
            let commonName = try CLIHelpers.value(after: "--identity-common-name", in: arguments)
            let report = try PolicySigner.doctorIdentity(commonName: commonName)
            guard report.identity.isTokenBacked else {
                throw CassPolicyError.preflightFailed("Identity '\(commonName)' is not token-backed.")
            }
            let policy = try PolicyLoader.loadPolicy(at: policyPath)
            let envelope = try PolicySigner.sign(policy: policy, using: try PolicySigner.loadIdentity(commonName: commonName))
            try PolicySigner.verify(envelope: envelope)
            try PolicyLoader.writeSignedPolicy(envelope, to: outputPath)
            try CLIHelpers.printJSON([
                "status": "ok",
                "output": outputPath,
                "signer": envelope.signature.signer,
                "key_source": envelope.signature.keySource,
            ])
        default:
            throw CassPolicyError.invalidCommand(arguments[1])
        }
    }

    private static func promote(_ arguments: [String]) throws {
        let layout = runtimeLayout(arguments)
        let sourcePath = try CLIHelpers.value(after: "--source", in: arguments)
        let targetPath = try CLIHelpers.value(after: "--target", in: arguments)
        let operationRaw = CLIHelpers.optionalValue(after: "--operation", in: arguments) ?? GovernedOperation.rename.rawValue
        let signedPolicyPath = CLIHelpers.optionalValue(after: "--signed-policy", in: arguments) ?? layout.activePolicyPath
        let dryRun = CLIHelpers.hasFlag("--dry-run", in: arguments)
        let verifierTimeout = Double(CLIHelpers.optionalValue(after: "--verifier-timeout-sec", in: arguments) ?? "10") ?? 10

        guard let operation = GovernedOperation(rawValue: operationRaw) else {
            throw CassPolicyError.invalidCommand("Unknown promotion operation '\(operationRaw)'.")
        }
        guard [.rename, .copyFile, .clone, .exchangeData].contains(operation) else {
            throw CassPolicyError.invalidCommand("Promotion operation must be rename, copyfile, clone, or exchange_data.")
        }

        let envelope = try PolicyLoader.loadSignedPolicy(at: signedPolicyPath)
        try PolicySigner.verify(envelope: envelope)
        let leaseStore = LeaseStore(layout: layout)
        let activeLeases = try leaseStore.activeLeases(for: envelope.policy.profile)
        let engine = PolicyEngine(policy: envelope.policy)
        let verifier = ProcessVerificationRunner(timeout: verifierTimeout)
        let event = RuntimeEvent(
            operation: operation,
            targetPath: targetPath,
            sourcePath: sourcePath
        )
        let decision = try engine.decide(event: event, verifier: verifier, activeLeases: activeLeases)

        let logger = AuditLogger(layout: layout)
        if decision.action == .deny {
            try logger.append(
                AuditRecord(
                    recordedAt: CassTime.string(),
                    category: "promotion-deny",
                    leaseID: decision.matchedLeaseID,
                    ruleID: decision.matchedRuleID,
                    outcome: "denied",
                    detail: decision.detail ?? targetPath
                )
            )
            try CLIHelpers.printJSON(
                PromotionReport(
                    status: "denied",
                    source: sourcePath,
                    target: targetPath,
                    operation: operation.rawValue,
                    reason: decision.reason,
                    ruleID: decision.matchedRuleID,
                    leaseID: decision.matchedLeaseID,
                    detail: decision.detail,
                    verifierBypassed: nil
                )
            )
            exit(2)
        }

        if !dryRun {
            try applyPromotion(sourcePath: sourcePath, targetPath: targetPath)
        }

        try logger.append(
            AuditRecord(
                recordedAt: CassTime.string(),
                category: dryRun ? "promotion-dry-run" : "promotion-allow",
                leaseID: decision.matchedLeaseID,
                ruleID: decision.matchedRuleID,
                outcome: dryRun ? "dry_run" : "allowed",
                detail: decision.detail ?? targetPath
            )
        )
        try CLIHelpers.printJSON(
            PromotionReport(
                status: dryRun ? "dry_run_allowed" : "promoted",
                source: sourcePath,
                target: targetPath,
                operation: operation.rawValue,
                reason: decision.reason,
                ruleID: decision.matchedRuleID,
                leaseID: decision.matchedLeaseID,
                detail: decision.detail,
                verifierBypassed: decision.verifierBypassed
            )
        )
    }

    private static func lease(_ arguments: [String]) throws {
        guard arguments.count >= 2 else {
            throw CassPolicyError.invalidCommand("Expected `cassctl lease create`, `list`, or `revoke`.")
        }
        switch arguments[1] {
        case "create":
            let layout = runtimeLayout(arguments)
            let commonName = try CLIHelpers.value(after: "--identity-common-name", in: arguments)
            let reason = try CLIHelpers.value(after: "--reason", in: arguments)
            let duration = try CLIHelpers.value(after: "--duration", in: arguments)
            guard duration == "15m" else {
                throw CassPolicyError.invalidLease("Phase 1 leases are fixed to --duration 15m.")
            }
            let profileRaw = CLIHelpers.optionalValue(after: "--profile", in: arguments) ?? PolicyProfile.strict.rawValue
            guard let profile = PolicyProfile(rawValue: profileRaw) else {
                throw CassPolicyError.invalidLease("Unknown profile '\(profileRaw)'.")
            }
            let operations = try CLIHelpers.commaSeparatedValues(after: "--ops", in: arguments).map(parseOperation)
            let paths = try CLIHelpers.commaSeparatedValues(after: "--paths", in: arguments)
            let bypassVerifier = CLIHelpers.hasFlag("--bypass-verifier", in: arguments)
            let identityReport = try PolicySigner.doctorIdentity(commonName: commonName)
            guard identityReport.identity.isTokenBacked else {
                throw CassPolicyError.preflightFailed("Identity '\(commonName)' is not token-backed.")
            }

            let lease = BreakglassLease(
                leaseID: UUID().uuidString.lowercased(),
                profile: profile,
                createdAt: CassTime.string(),
                expiresAt: CassTime.string(from: Date().addingTimeInterval(15 * 60)),
                pathPatterns: paths,
                operations: operations,
                bypassVerifier: bypassVerifier,
                reason: reason
            )
            let envelope = try PolicySigner.sign(lease: lease, using: try PolicySigner.loadIdentity(commonName: commonName))
            try PolicySigner.verify(leaseEnvelope: envelope)

            let leaseStore = LeaseStore(layout: layout)
            try leaseStore.save(envelope)
            try AuditLogger(layout: layout).append(
                AuditRecord(
                    recordedAt: CassTime.string(),
                    category: "lease-create",
                    leaseID: lease.leaseID,
                    outcome: "created",
                    detail: reason
                )
            )
            try CLIHelpers.printJSON(envelope)

        case "list":
            let layout = runtimeLayout(arguments)
            let leaseStore = LeaseStore(layout: layout)
            try CLIHelpers.printJSON(try leaseStore.list())

        case "revoke":
            let layout = runtimeLayout(arguments)
            let leaseID = try CLIHelpers.value(after: "--lease-id", in: arguments)
            let reason = CLIHelpers.optionalValue(after: "--reason", in: arguments) ?? "revoked"
            let leaseStore = LeaseStore(layout: layout)
            try leaseStore.revoke(leaseID: leaseID, reason: reason)
            try AuditLogger(layout: layout).append(
                AuditRecord(
                    recordedAt: CassTime.string(),
                    category: "lease-revoke",
                    leaseID: leaseID,
                    outcome: "revoked",
                    detail: reason
                )
            )
            try CLIHelpers.printJSON([
                "status": "ok",
                "lease_id": leaseID,
                "reason": reason,
            ])

        default:
            throw CassPolicyError.invalidCommand(arguments[1])
        }
    }

    private static func refreshedStatus(
        from stored: StatusReport,
        layout: CassRuntimeLayout,
        deployment: CassDeploymentConfig,
        signedPolicyPath: String,
        leaseStore: LeaseStore
    ) throws -> StatusReport {
        var report = stored
        report.generatedAt = CassTime.string()
        report.hostAppPath = deployment.hostAppPath
        report.runtimeRoot = layout.rootDirectory
        report.activeLeaseCount = (try? leaseStore.activeLeases().count) ?? 0
        report.checks = deduplicateChecks([
            runtimeOwnershipCheck(layout: layout),
        ])

        if FileManager.default.fileExists(atPath: signedPolicyPath),
           let envelope = try? PolicyLoader.loadSignedPolicy(at: signedPolicyPath) {
            do {
                try PolicySigner.verify(envelope: envelope)
                report.signedPolicyPath = signedPolicyPath
                report.loadedProfile = envelope.policy.profile
                report.memoryControl = envelope.policy.memoryControl
                report.policyFingerprint = try RuntimeSupport.fingerprint(for: envelope)
                if report.activationState == .inactive || report.activationState == .policyInstalled {
                    report.activationState = .policyInstalled
                }
            } catch {
                report.activationState = .broken
            }
        } else if report.activationState == .policyInstalled {
            report.activationState = .inactive
        }

        if report.activationState != .inactive && !FileManager.default.fileExists(atPath: deployment.hostAppPath) {
            report.hostAppPath = deployment.hostAppPath
        }

        try PolicyLoader.writeJSON(report, to: layout.statusPath)
        return report
    }

    private static func status(from report: DoctorReport, layout: CassRuntimeLayout) -> StatusReport {
        StatusReport(
            generatedAt: report.generatedAt,
            activationState: FileManager.default.fileExists(atPath: layout.activationRequestPath)
                ? .activationRequested
                : (FileManager.default.fileExists(atPath: layout.activePolicyPath) ? .policyInstalled : .inactive),
            runtimeRoot: report.runtimeRoot,
            hostAppPath: report.hostAppPath,
            checks: report.checks
        )
    }

    private static func runtimeLayout(_ arguments: [String]) -> CassRuntimeLayout {
        CassRuntimeLayout(
            rootDirectory: CLIHelpers.optionalValue(after: "--runtime-root", in: arguments)
                ?? CassRuntimeLayout.production().rootDirectory
        )
    }

    private static func deploymentConfig(_ arguments: [String]) -> CassDeploymentConfig {
        CassDeploymentConfig(
            hostAppPath: CLIHelpers.optionalValue(after: "--host-app-path", in: arguments) ?? CassDeploymentConfig.production.hostAppPath,
            hostAppBundleIdentifier: CLIHelpers.optionalValue(after: "--host-app-bundle-id", in: arguments) ?? CassDeploymentConfig.production.hostAppBundleIdentifier,
            systemExtensionBundleIdentifier: CLIHelpers.optionalValue(after: "--extension-bundle-id", in: arguments) ?? CassDeploymentConfig.production.systemExtensionBundleIdentifier
        )
    }

    private static func runtimeOwnershipCheck(layout: CassRuntimeLayout) -> DoctorCheck {
        guard FileManager.default.fileExists(atPath: layout.rootDirectory) else {
            return DoctorCheck(
                id: "runtime-root",
                status: .fail,
                summary: "Runtime root does not exist.",
                detail: layout.rootDirectory,
                remediation: "Create the runtime root under /Library/Application Support/com.orxaq.cass and ensure it is root-owned."
            )
        }
        let ownerID = RuntimeSupport.ownerAccountID(for: layout.rootDirectory)
        let ok = ownerID == 0
        return DoctorCheck(
            id: "runtime-root",
            status: ok ? .pass : .fail,
            summary: ok ? "Runtime root is root-owned." : "Runtime root ownership is not root.",
            detail: ownerID.map { "owner_uid=\($0)" } ?? "owner unavailable",
            remediation: "Ensure the runtime root is created and owned by root before live activation."
        )
    }

    private static func hostAppPresenceCheck(deployment: CassDeploymentConfig) -> DoctorCheck {
        let exists = FileManager.default.fileExists(atPath: deployment.hostAppPath)
        return DoctorCheck(
            id: "host-app",
            status: exists ? .pass : .fail,
            summary: exists ? "Host app is installed." : "Host app is not installed in /Applications.",
            detail: deployment.hostAppPath,
            remediation: "Build and install the signed host app bundle in /Applications before requesting live activation."
        )
    }

    private static func appleTeamCheck(deployment: CassDeploymentConfig) -> DoctorCheck {
        guard FileManager.default.fileExists(atPath: deployment.hostAppPath) else {
            return DoctorCheck(
                id: "apple-team",
                status: .fail,
                summary: "Apple team identity could not be verified because the host app is not installed.",
                remediation: "Enroll in the Apple Developer Program, sign the host app, and install it before activation."
            )
        }
        let result = runProcess("/usr/bin/codesign", ["-dv", deployment.hostAppPath])
        let output = result.stdout + result.stderr
        let hasTeamIdentifier = output.contains("TeamIdentifier=") && !output.contains("TeamIdentifier=not set")
        return DoctorCheck(
            id: "apple-team",
            status: hasTeamIdentifier ? .pass : .fail,
            summary: hasTeamIdentifier ? "Host app is signed with an Apple team identity." : "Host app is not signed with an Apple team identity.",
            detail: output.trimmingCharacters(in: .whitespacesAndNewlines),
            remediation: "Sign the host app with Apple Developer assets for a real team before live activation."
        )
    }

    private static func managedEntitlementCheck(deployment: CassDeploymentConfig) -> DoctorCheck {
        guard let extensionPath = firstSystemExtensionPath(inHostApp: deployment.hostAppPath) else {
            return DoctorCheck(
                id: "managed-endpoint-security-entitlement",
                status: .fail,
                summary: "System extension bundle is not installed under the host app.",
                remediation: "Build the signed Endpoint Security system extension and embed it in the host app bundle."
            )
        }
        let result = runProcess("/usr/bin/codesign", ["-d", "--entitlements", ":-", extensionPath])
        let output = result.stdout + result.stderr
        let hasEntitlement = output.contains("com.apple.developer.endpoint-security.client")
        return DoctorCheck(
            id: "managed-endpoint-security-entitlement",
            status: hasEntitlement ? .pass : .fail,
            summary: hasEntitlement ? "Managed Endpoint Security entitlement is present." : "Managed Endpoint Security entitlement is missing.",
            detail: output.trimmingCharacters(in: .whitespacesAndNewlines),
            remediation: "Request the managed Endpoint Security entitlement from Apple and sign the system extension with it."
        )
    }

    private static func provisioningAssetsCheck(deployment: CassDeploymentConfig) -> DoctorCheck {
        guard FileManager.default.fileExists(atPath: deployment.hostAppPath) else {
            return DoctorCheck(
                id: "provisioning-assets",
                status: .fail,
                summary: "Provisioning assets could not be checked because the host app is missing.",
                remediation: "Build and install the signed host app with embedded provisioning profiles."
            )
        }

        let hostProfile = "\(deployment.hostAppPath)/Contents/embedded.provisionprofile"
        let extensionProfile = firstSystemExtensionPath(inHostApp: deployment.hostAppPath)
            .map { "\($0)/Contents/embedded.provisionprofile" }
        let ok = FileManager.default.fileExists(atPath: hostProfile)
            && extensionProfile.map { FileManager.default.fileExists(atPath: $0) } == true
        return DoctorCheck(
            id: "provisioning-assets",
            status: ok ? .pass : .fail,
            summary: ok ? "Provisioning profiles are embedded in the host app and system extension." : "Provisioning profiles are missing from the host app or system extension.",
            detail: [hostProfile, extensionProfile].compactMap { $0 }.joined(separator: "\n"),
            remediation: "Build the app and system extension with valid provisioning profiles before activation."
        )
    }

    private static func anyYubiKeyIdentityCheck() -> DoctorCheck {
        do {
            let identities = try PolicySigner.listIdentities().filter(\.isTokenBacked)
            let ok = !identities.isEmpty
            return DoctorCheck(
                id: "yubikey-identity",
                status: ok ? .pass : .fail,
                summary: ok ? "At least one token-backed signing identity is available." : "No token-backed signing identity was found.",
                detail: identities.map(\.commonName).joined(separator: ", "),
                remediation: "Expose the YubiKey PIV identity to Keychain via CryptoTokenKit before activation."
            )
        } catch {
            return DoctorCheck(
                id: "yubikey-identity",
                status: .fail,
                summary: "Unable to enumerate signing identities.",
                detail: error.localizedDescription,
                remediation: "Insert the YubiKey, expose its PIV identity to Keychain, and retry."
            )
        }
    }

    private static func yubiKeyIdentityCheck(commonName: String) -> DoctorCheck {
        do {
            let report = try PolicySigner.doctorIdentity(commonName: commonName)
            let ok = report.identity.isTokenBacked && report.signingChallengePassed
            return DoctorCheck(
                id: "yubikey-identity",
                status: ok ? .pass : .fail,
                summary: ok ? "Token-backed YubiKey identity is usable." : "Signing identity is not usable as a YubiKey-backed authority.",
                detail: report.certificateTrustDetail,
                remediation: "Use a CryptoTokenKit-exposed YubiKey PIV identity that can complete a signing challenge."
            )
        } catch {
            return DoctorCheck(
                id: "yubikey-identity",
                status: .fail,
                summary: "YubiKey identity validation failed.",
                detail: error.localizedDescription,
                remediation: "Confirm the specified common name exists in Keychain and is backed by the inserted YubiKey."
            )
        }
    }

    private static func launchHostAppIfPresent(
        deployment: CassDeploymentConfig,
        activationRequestPath: String? = nil,
        deactivationRequestPath: String? = nil
    ) throws -> Bool {
        guard FileManager.default.fileExists(atPath: deployment.hostAppPath) else {
            return false
        }

        var arguments = ["-a", deployment.hostAppPath, "--args"]
        if let deactivationRequestPath {
            arguments.append(contentsOf: ["--cass-deactivate-request", deactivationRequestPath])
        } else if let activationRequestPath {
            arguments.append(contentsOf: ["--cass-activate-request", activationRequestPath])
        } else {
            return false
        }

        let result = runProcess("/usr/bin/open", arguments)
        if result.status != 0 {
            throw CassPolicyError.activationFailed(result.stderr.isEmpty ? "Unable to launch the host app." : result.stderr)
        }
        return true
    }

    private static func firstSystemExtensionPath(inHostApp hostAppPath: String) -> String? {
        let directory = "\(hostAppPath)/Contents/Library/SystemExtensions"
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: directory) else {
            return nil
        }
        return entries
            .filter { $0.hasSuffix(".systemextension") }
            .sorted()
            .map { "\(directory)/\($0)" }
            .first
    }

    private static func runProcess(_ executable: String, _ arguments: [String]) -> (status: Int32, stdout: String, stderr: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return (status: 1, stdout: "", stderr: error.localizedDescription)
        }

        let stdout = String(data: stdoutPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: stderrPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return (status: process.terminationStatus, stdout: stdout, stderr: stderr)
    }

    private static func parseOperation(_ rawValue: String) throws -> GovernedOperation {
        guard let operation = GovernedOperation(rawValue: rawValue) else {
            throw CassPolicyError.invalidLease("Unknown governed operation '\(rawValue)'.")
        }
        return operation
    }

    private static func deduplicateChecks(_ checks: [DoctorCheck]) -> [DoctorCheck] {
        var seen = Set<String>()
        return checks.filter { check in
            seen.insert(check.id).inserted
        }
    }

    private static func applyPromotion(sourcePath: String, targetPath: String) throws {
        let fileManager = FileManager.default
        let sourceURL = URL(fileURLWithPath: sourcePath)
        let targetURL = URL(fileURLWithPath: targetPath)
        let targetDirectory = targetURL.deletingLastPathComponent()
        try fileManager.createDirectory(at: targetDirectory, withIntermediateDirectories: true)

        let stagingURL = targetDirectory.appendingPathComponent(".cass-promotion-\(UUID().uuidString)")
        if fileManager.fileExists(atPath: stagingURL.path) {
            try fileManager.removeItem(at: stagingURL)
        }
        try fileManager.copyItem(at: sourceURL, to: stagingURL)

        if fileManager.fileExists(atPath: targetURL.path) {
            _ = try fileManager.replaceItemAt(targetURL, withItemAt: stagingURL)
        } else {
            try fileManager.moveItem(at: stagingURL, to: targetURL)
        }
    }

    private static func ensureActivationPreflight(
        layout: CassRuntimeLayout,
        deployment: CassDeploymentConfig,
        identityCommonName: String
    ) throws {
        let checks = [
            runtimeOwnershipCheck(layout: layout),
            hostAppPresenceCheck(deployment: deployment),
            appleTeamCheck(deployment: deployment),
            managedEntitlementCheck(deployment: deployment),
            provisioningAssetsCheck(deployment: deployment),
            yubiKeyIdentityCheck(commonName: identityCommonName),
        ]

        let failures = checks.filter { $0.status == .fail }
        guard failures.isEmpty else {
            let details = failures.map { check in
                let detail = check.detail.map { " (\($0))" } ?? ""
                return "[\(check.id)] \(check.summary)\(detail)"
            }.joined(separator: "; ")
            throw CassPolicyError.preflightFailed(details)
        }

        let leaseStore = LeaseStore(layout: layout)
        do {
            try leaseStore.validate()
        } catch {
            throw CassPolicyError.preflightFailed("[lease-store] \(error.localizedDescription)")
        }
    }
}

do {
    try CassCtlCLI.main()
} catch {
    fputs("cassctl: \(error.localizedDescription)\n", stderr)
    exit(1)
}
