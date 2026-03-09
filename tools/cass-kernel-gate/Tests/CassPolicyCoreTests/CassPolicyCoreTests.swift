@testable import CassPolicyCore
import Foundation
import Security
import Testing

struct CassPolicyCoreTests {
    @Test
    func strictPolicyIncludesPersonalGovernanceAndEvidenceButNotMemory() throws {
        let policy = PolicyFactory.makeClaudeCodePolicy(
            homeDirectory: "/Users/tester",
            repoDirectory: "/Users/tester/dev/orxaq",
            verifierPath: "/Users/tester/dev/orxaq/.claude/hooks/cass_code_verify.sh",
            profile: .strict
        )

        #expect(policy.profile == .strict)
        #expect(policy.memoryControl == .disabled)
        #expect(policy.governedPaths.contains { $0.pathPattern == "/Users/tester/.claude/settings.json" })
        #expect(policy.governedPaths.contains { $0.pathPattern == "/Users/tester/Documents/Orxaq/obsidian_vault/Violations/**" })
        #expect(!policy.governedPaths.contains { $0.pathPattern.contains("MEMORY.md") })
    }

    @Test
    func collaboratorPolicyRestrictsGovernanceToRepoOnly() throws {
        let policy = PolicyFactory.makeClaudeCodePolicy(
            homeDirectory: "/Users/tester",
            repoDirectory: "/Users/tester/dev/orxaq",
            verifierPath: "/Users/tester/dev/orxaq/.claude/hooks/cass_code_verify.sh",
            profile: .collaborator
        )

        #expect(policy.profile == .collaborator)
        #expect(!policy.governedPaths.contains { $0.pathPattern.hasPrefix("/Users/tester/.claude") })
        #expect(!policy.governedPaths.contains { $0.pathPattern.contains("obsidian_vault/Violations") })
        #expect(policy.governedPaths.contains { $0.pathPattern == "/Users/tester/dev/orxaq/.claude/rules/**" })
        #expect(policy.governedPaths.contains { $0.pathPattern == "/Users/tester/dev/orxaq/.claude/agents/**" })
    }

    @Test
    func referenceDocsRemainWritable() throws {
        let policy = PolicyFactory.makeClaudeCodePolicy(
            homeDirectory: "/Users/tester",
            repoDirectory: "/Users/tester/dev/orxaq",
            verifierPath: "/Users/tester/dev/orxaq/.claude/hooks/cass_code_verify.sh",
            profile: .strict
        )

        #expect(policy.writableReferencePaths.contains("/Users/tester/dev/orxaq/.claude/codebase-map.md"))
        #expect(!policy.governedPaths.contains { $0.pathPattern == "/Users/tester/dev/orxaq/.claude/codebase-map.md" })
    }

    @Test
    func yubikeySlotResolverMapsCanonicalCassNames() throws {
        #expect(DirectYubiKeySlotResolver.slot(forCommonName: "Orxaq CASS Policy") == 0x9c)
        #expect(DirectYubiKeySlotResolver.slot(forCommonName: "Orxaq CASS Authentication") == 0x9a)
        #expect(DirectYubiKeySlotResolver.slot(forCommonName: "Orxaq CASS Key Management") == 0x9d)
    }

    @Test
    func yubikeySlotResolverHonorsExplicitOverride() throws {
        setenv("CASS_YUBIKEY_SLOT_Custom_Signer", "0x9c", 1)
        defer { unsetenv("CASS_YUBIKEY_SLOT_Custom_Signer") }

        #expect(DirectYubiKeySlotResolver.slot(forCommonName: "Custom Signer") == 0x9c)
    }

    @Test
    func pathMatcherHandlesExactGlobAndUnicodeNormalization() throws {
        #expect(PathMatcher.matches(glob: "/tmp/.claude/settings.json", path: "/tmp/.claude/settings.json"))
        #expect(PathMatcher.matches(glob: "/repo/.claude/rules/**", path: "/repo/.claude/rules/python/tier-system.md"))

        let decomposed = "Cafe\u{301}.md"
        let composed = "Café.md"
        #expect(PathMatcher.matches(glob: "/tmp/\(composed)", path: "/tmp/\(decomposed)"))
    }

    @Test
    func pathMatcherResolvesSymlinkTargets() throws {
        let tempDirectory = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(atPath: tempDirectory) }

        let governedDirectory = "\(tempDirectory)/real"
        let symlinkDirectory = "\(tempDirectory)/link"
        try FileManager.default.createDirectory(atPath: governedDirectory, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: symlinkDirectory, withDestinationPath: governedDirectory)

        let governedFile = "\(symlinkDirectory)/settings.json"
        #expect(PathMatcher.matches(glob: "\(governedDirectory)/*", path: governedFile))
    }

    @Test
    func governedWriteIsDenied() throws {
        let engine = PolicyEngine(policy: fixturePolicy())
        let decision = try engine.decide(
            event: RuntimeEvent(operation: .openWrite, targetPath: "/tmp/.claude/settings.json")
        )
        #expect(decision.action == PolicyAction.deny)
        #expect(decision.matchedRuleID == "settings")
    }

    @Test
    func commandRuleDeniesUnlockAttempt() throws {
        let engine = PolicyEngine(policy: fixturePolicy(commandRules: [
            CommandRule(
                id: "deny-chflags",
                commandRegex: #"(^|.*\s)chflags\s+nouchg(\s|$)"#,
                action: .deny,
                reason: "immutable unlock denied"
            ),
        ]))
        let decision = try engine.decide(
            event: RuntimeEvent(operation: .exec, argv: ["/bin/zsh", "-lc", "chflags nouchg /tmp/.claude/settings.json"])
        )
        #expect(decision.action == PolicyAction.deny)
        #expect(decision.matchedRuleID == "deny-chflags")
    }

    @Test
    func directPythonWritesAreDenied() throws {
        let engine = PolicyEngine(policy: fixturePolicy(verificationRules: [
            VerificationRule(
                id: "verify-python",
                targetPathRegex: #"^/repo/.*\.py$"#,
                verifierCommand: ["/bin/true"],
                reason: "verify"
            ),
        ]))

        let decision = try engine.decide(
            event: RuntimeEvent(operation: .openWrite, targetPath: "/repo/module.py")
        )
        #expect(decision.action == PolicyAction.deny)
        #expect(decision.matchedRuleID == "verify-python")
    }

    @Test
    func stagedPromotionAllowsOnVerifierSuccess() throws {
        let engine = PolicyEngine(policy: fixturePolicy(verificationRules: [
            VerificationRule(
                id: "verify-python",
                targetPathRegex: #"^/repo/.*\.py$"#,
                verifierCommand: ["/verify"],
                reason: "verify"
            ),
        ]))

        let decision = try engine.decide(
            event: RuntimeEvent(operation: .rename, targetPath: "/repo/module.py", sourcePath: "/tmp/candidate.py"),
            verifier: StubVerifierRunner(outcome: .allow(detail: "clean"))
        )
        #expect(decision.action == PolicyAction.allow)
        #expect(decision.matchedRuleID == "verify-python")
    }

    @Test
    func stagedPromotionFailsClosedOnVerifierDeny() throws {
        let engine = PolicyEngine(policy: fixturePolicy(verificationRules: [
            VerificationRule(
                id: "verify-python",
                targetPathRegex: #"^/repo/.*\.py$"#,
                verifierCommand: ["/verify"],
                reason: "verify"
            ),
        ]))

        let decision = try engine.decide(
            event: RuntimeEvent(operation: .rename, targetPath: "/repo/module.py", sourcePath: "/tmp/candidate.py"),
            verifier: StubVerifierRunner(outcome: .deny(detail: "blocked"))
        )
        #expect(decision.action == PolicyAction.deny)
        #expect(decision.matchedRuleID == "verify-python")
    }

    @Test
    func verifierInfrastructureFailureFailsClosed() throws {
        let engine = PolicyEngine(policy: fixturePolicy(verificationRules: [
            VerificationRule(
                id: "verify-python",
                targetPathRegex: #"^/repo/.*\.py$"#,
                verifierCommand: ["/verify"],
                reason: "verify"
            ),
        ]))

        let decision = try engine.decide(
            event: RuntimeEvent(operation: .rename, targetPath: "/repo/module.py", sourcePath: "/tmp/candidate.py"),
            verifier: StubVerifierRunner(outcome: .infrastructureFailure(detail: "invalid verifier output"))
        )
        #expect(decision.action == PolicyAction.deny)
        #expect(decision.reason.contains("failed closed"))
    }

    @Test
    func processVerifierProvidesHookStyleInputAndProjectDirectory() throws {
        let tempDirectory = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(atPath: tempDirectory) }

        let repoDirectory = "\(tempDirectory)/repo"
        let hooksDirectory = "\(repoDirectory)/.claude/hooks"
        try FileManager.default.createDirectory(atPath: hooksDirectory, withIntermediateDirectories: true)

        let verifierPath = "\(hooksDirectory)/cass_code_verify.sh"
        let script = """
        #!/bin/zsh
        set -euo pipefail
        [[ "${CLAUDE_PROJECT_DIR}" == "\(repoDirectory)" ]] || exit 9
        input=$(cat)
        python3 -c 'import json, os, sys; data = json.loads(sys.argv[1]); assert data["tool_input"]["file_path"].endswith("module.py"); assert data["tool_input"]["candidate_path"].endswith("candidate.py"); assert os.environ["CASS_TARGET_PATH"].endswith("module.py"); print("ok")' "$input"
        """
        try script.write(toFile: verifierPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: verifierPath)

        let runner = ProcessVerificationRunner()
        let outcome = try runner.run(
            command: [verifierPath],
            sourcePath: "\(tempDirectory)/candidate.py",
            targetPath: "\(repoDirectory)/module.py"
        )
        #expect(outcome == .allow(detail: "ok"))
    }

    @Test
    func breakglassLeaseOverridesPathDeny() throws {
        let policy = fixturePolicy()
        let engine = PolicyEngine(policy: policy)
        let lease = BreakglassLease(
            leaseID: "lease-1",
            profile: .strict,
            createdAt: CassTime.string(from: Date().addingTimeInterval(-60)),
            expiresAt: CassTime.string(from: Date().addingTimeInterval(60)),
            pathPatterns: ["/tmp/.claude/settings.json"],
            operations: [.openWrite],
            bypassVerifier: false,
            reason: "temporary override"
        )

        let decision = try engine.decide(
            event: RuntimeEvent(operation: .openWrite, targetPath: "/tmp/.claude/settings.json"),
            activeLeases: [lease]
        )
        #expect(decision.action == PolicyAction.allow)
        #expect(decision.matchedLeaseID == "lease-1")
    }

    @Test
    func verifierBypassRequiresExplicitLeaseFlag() throws {
        let policy = fixturePolicy(verificationRules: [
            VerificationRule(
                id: "verify-python",
                targetPathRegex: #"^/repo/.*\.py$"#,
                verifierCommand: ["/verify"],
                reason: "verify"
            ),
        ])
        let engine = PolicyEngine(policy: policy)
        let strictLease = BreakglassLease(
            leaseID: "lease-plain",
            profile: .strict,
            createdAt: CassTime.string(from: Date().addingTimeInterval(-60)),
            expiresAt: CassTime.string(from: Date().addingTimeInterval(60)),
            pathPatterns: ["/repo/*.py"],
            operations: [.rename],
            bypassVerifier: false,
            reason: "no verifier bypass"
        )

        let denied = try engine.decide(
            event: RuntimeEvent(operation: .rename, targetPath: "/repo/module.py", sourcePath: "/tmp/candidate.py"),
            verifier: StubVerifierRunner(outcome: .deny(detail: "blocked")),
            activeLeases: [strictLease]
        )
        #expect(denied.action == PolicyAction.deny)

        let bypassLease = BreakglassLease(
            leaseID: "lease-bypass",
            profile: .strict,
            createdAt: CassTime.string(from: Date().addingTimeInterval(-60)),
            expiresAt: CassTime.string(from: Date().addingTimeInterval(60)),
            pathPatterns: ["/repo/*.py"],
            operations: [.rename],
            bypassVerifier: true,
            reason: "allow the hotfix"
        )
        let allowed = try engine.decide(
            event: RuntimeEvent(operation: .rename, targetPath: "/repo/module.py", sourcePath: "/tmp/candidate.py"),
            verifier: StubVerifierRunner(outcome: .deny(detail: "blocked")),
            activeLeases: [bypassLease]
        )
        #expect(allowed.action == PolicyAction.allow)
        #expect(allowed.verifierBypassed)
        #expect(allowed.matchedLeaseID == "lease-bypass")
    }

    @Test
    func overlappingLeasesResolveDeterministically() throws {
        let policy = fixturePolicy()
        let engine = PolicyEngine(policy: policy)
        let now = Date()
        let broad = BreakglassLease(
            leaseID: "broad",
            profile: .strict,
            createdAt: CassTime.string(from: now.addingTimeInterval(-120)),
            expiresAt: CassTime.string(from: now.addingTimeInterval(120)),
            pathPatterns: ["/tmp/.claude/*"],
            operations: [.openWrite],
            bypassVerifier: false,
            reason: "broad"
        )
        let specific = BreakglassLease(
            leaseID: "specific",
            profile: .strict,
            createdAt: CassTime.string(from: now.addingTimeInterval(-60)),
            expiresAt: CassTime.string(from: now.addingTimeInterval(180)),
            pathPatterns: ["/tmp/.claude/settings.json"],
            operations: [.openWrite],
            bypassVerifier: false,
            reason: "specific"
        )
        let decision = try engine.decide(
            event: RuntimeEvent(operation: .openWrite, targetPath: "/tmp/.claude/settings.json"),
            activeLeases: [broad, specific]
        )
        #expect(decision.matchedLeaseID == "specific")
    }

    @Test
    func execLeaseCanOverrideCommandDenialWhenScopedPathAppearsInShellString() throws {
        let policy = fixturePolicy(commandRules: [
            CommandRule(
                id: "deny-rm-violations",
                commandRegex: #".*\brm\s+.*obsidian_vault/Violations/.*"#,
                action: .deny,
                reason: "deny"
            ),
        ])
        let engine = PolicyEngine(policy: policy)
        let lease = BreakglassLease(
            leaseID: "lease-exec",
            profile: .strict,
            createdAt: CassTime.string(from: Date().addingTimeInterval(-60)),
            expiresAt: CassTime.string(from: Date().addingTimeInterval(60)),
            pathPatterns: ["/Users/tester/Documents/Orxaq/obsidian_vault/Violations/**"],
            operations: [.exec],
            bypassVerifier: false,
            reason: "cleanup"
        )
        let decision = try engine.decide(
            event: RuntimeEvent(
                operation: .exec,
                argv: ["/bin/zsh", "-lc", "rm /Users/tester/Documents/Orxaq/obsidian_vault/Violations/test.md"]
            ),
            activeLeases: [lease]
        )
        #expect(decision.action == PolicyAction.allow)
        #expect(decision.matchedLeaseID == "lease-exec")
    }

    @Test
    func leaseStoreTracksRevocationAndExpiry() throws {
        let tempDirectory = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(atPath: tempDirectory) }

        let layout = CassRuntimeLayout(rootDirectory: tempDirectory)
        let store = LeaseStore(layout: layout)
        let envelope = try signedLease(
            leaseID: "lease-1",
            createdAt: CassTime.string(from: Date().addingTimeInterval(-60)),
            expiresAt: CassTime.string(from: Date().addingTimeInterval(60))
        )
        try store.save(envelope)
        #expect(try store.activeLeases().count == 1)

        try store.revoke(leaseID: "lease-1", reason: "done")
        #expect(try store.activeLeases().isEmpty)
    }

    @Test
    func tamperedLeaseFailsValidation() throws {
        let tempDirectory = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(atPath: tempDirectory) }

        let layout = CassRuntimeLayout(rootDirectory: tempDirectory)
        let store = LeaseStore(layout: layout)
        let envelope = try signedLease(
            leaseID: "lease-1",
            createdAt: CassTime.string(from: Date().addingTimeInterval(-60)),
            expiresAt: CassTime.string(from: Date().addingTimeInterval(60))
        )
        try store.save(envelope)

        let leasePath = "\(layout.leasesDirectory)/lease-1.signed.json"
        let data = try String(contentsOfFile: leasePath, encoding: .utf8).replacingOccurrences(of: "temporary override", with: "tampered override")
        try data.write(toFile: leasePath, atomically: true, encoding: .utf8)

        var failed = false
        do {
            _ = try store.list()
        } catch {
            failed = true
        }
        #expect(failed)
    }

    @Test
    func signAndVerifyRoundTrip() throws {
        let material = try ephemeralSigningMaterial()
        let policy = fixturePolicy()
        let envelope = try PolicySigner.sign(policy: policy, using: material)
        try PolicySigner.verify(envelope: envelope)
        #expect(envelope.signature.signer == "unit-test")
    }

    @Test
    func tamperedPolicySignatureFailsVerification() throws {
        let material = try ephemeralSigningMaterial()
        let policy = fixturePolicy()
        let envelope = try PolicySigner.sign(policy: policy, using: material)

        let tampered = SignedPolicyEnvelope(
            policy: PolicyDocument(
                policyID: envelope.policy.policyID,
                createdAt: envelope.policy.createdAt,
                description: "tampered",
                profile: envelope.policy.profile,
                memoryControl: envelope.policy.memoryControl,
                monitoredExecutables: envelope.policy.monitoredExecutables,
                governedPaths: envelope.policy.governedPaths,
                governedCommands: envelope.policy.governedCommands,
                verificationRules: envelope.policy.verificationRules,
                writableReferencePaths: envelope.policy.writableReferencePaths
            ),
            signature: envelope.signature
        )

        var failed = false
        do {
            try PolicySigner.verify(envelope: tampered)
        } catch {
            failed = true
        }
        #expect(failed)
    }

    @Test
    func runtimeStatusFingerprintIsStable() throws {
        let material = try ephemeralSigningMaterial()
        let envelope = try PolicySigner.sign(policy: fixturePolicy(), using: material)
        let fingerprint1 = try RuntimeSupport.fingerprint(for: envelope)
        let fingerprint2 = try RuntimeSupport.fingerprint(for: envelope)
        #expect(fingerprint1 == fingerprint2)
    }
}

private struct StubVerifierRunner: VerificationRunner {
    let outcome: VerificationOutcome

    func run(command: [String], sourcePath: String, targetPath: String) throws -> VerificationOutcome {
        outcome
    }
}

private func fixturePolicy(
    commandRules: [CommandRule] = [],
    verificationRules: [VerificationRule] = []
) -> PolicyDocument {
    PolicyDocument(
        policyID: "test",
        createdAt: "2026-03-08T00:00:00Z",
        description: "test",
        profile: .strict,
        monitoredExecutables: [],
        governedPaths: [
            GovernedPathRule(
                id: "settings",
                pathPattern: "/tmp/.claude/settings.json",
                operations: [.openWrite],
                action: .deny,
                reason: "settings locked"
            ),
        ],
        governedCommands: commandRules,
        verificationRules: verificationRules
    )
}

private func makeTempDirectory() throws -> String {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
    try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
    return directory
}

private func ephemeralSigningMaterial() throws -> SigningKeyMaterial {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
    ]
    var error: Unmanaged<CFError>?
    let privateKey = try #require(
        SecKeyCreateRandomKey(attributes as CFDictionary, &error),
        "\(error?.takeRetainedValue().localizedDescription ?? "key generation failed")"
    )
    let publicKey = try #require(SecKeyCopyPublicKey(privateKey))
    return SigningKeyMaterial(
        securityPrivateKey: privateKey,
        publicKey: publicKey,
        signer: "unit-test",
        keySource: "software"
    )
}

private func signedLease(leaseID: String, createdAt: String, expiresAt: String) throws -> SignedBreakglassLeaseEnvelope {
    let lease = BreakglassLease(
        leaseID: leaseID,
        profile: .strict,
        createdAt: createdAt,
        expiresAt: expiresAt,
        pathPatterns: ["/tmp/.claude/settings.json"],
        operations: [.openWrite],
        bypassVerifier: false,
        reason: "temporary override"
    )
    return try PolicySigner.sign(lease: lease, using: ephemeralSigningMaterial())
}
