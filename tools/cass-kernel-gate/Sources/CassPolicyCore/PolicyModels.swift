import Foundation

public enum CassPolicyError: Error, LocalizedError {
    case invalidUTF8
    case missingArgument(String)
    case invalidCommand(String)
    case invalidPolicy(String)
    case invalidLease(String)
    case signerNotFound(String)
    case signingFailed(String)
    case verificationFailed(String)
    case verifierExecutionFailed(String)
    case runtimeState(String)
    case preflightFailed(String)
    case activationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .invalidUTF8:
            return "Unable to decode UTF-8 data."
        case .missingArgument(let argument):
            return "Missing required argument: \(argument)"
        case .invalidCommand(let command):
            return "Invalid command: \(command)"
        case .invalidPolicy(let message):
            return "Invalid policy: \(message)"
        case .invalidLease(let message):
            return "Invalid lease: \(message)"
        case .signerNotFound(let message):
            return "Signer not found: \(message)"
        case .signingFailed(let message):
            return "Signing failed: \(message)"
        case .verificationFailed(let message):
            return "Verification failed: \(message)"
        case .verifierExecutionFailed(let message):
            return "Verifier execution failed: \(message)"
        case .runtimeState(let message):
            return "Runtime state error: \(message)"
        case .preflightFailed(let message):
            return "Preflight failed: \(message)"
        case .activationFailed(let message):
            return "Activation failed: \(message)"
        }
    }
}

public enum PolicyProfile: String, Codable, CaseIterable, Comparable {
    case strict
    case collaborator

    public static func < (lhs: PolicyProfile, rhs: PolicyProfile) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

public enum MemoryControlMode: String, Codable, CaseIterable, Comparable {
    case disabled
    case appendOnly = "append_only"
    case locked

    public static func < (lhs: MemoryControlMode, rhs: MemoryControlMode) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

public enum GovernedOperation: String, Codable, CaseIterable, Comparable {
    case openWrite = "open_write"
    case create = "create"
    case rename = "rename"
    case unlink = "unlink"
    case truncate = "truncate"
    case setFlags = "set_flags"
    case setMode = "set_mode"
    case setExtAttr = "set_extattr"
    case copyFile = "copyfile"
    case clone = "clone"
    case exchangeData = "exchange_data"
    case exec = "exec"

    public static func < (lhs: GovernedOperation, rhs: GovernedOperation) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

public enum PolicyAction: String, Codable {
    case allow
    case deny
}

public struct GovernedPathRule: Codable, Equatable {
    public var id: String
    public var pathPattern: String
    public var operations: [GovernedOperation]
    public var action: PolicyAction
    public var reason: String

    public init(
        id: String,
        pathPattern: String,
        operations: [GovernedOperation],
        action: PolicyAction,
        reason: String
    ) {
        self.id = id
        self.pathPattern = pathPattern
        self.operations = operations.sorted()
        self.action = action
        self.reason = reason
    }
}

public struct CommandRule: Codable, Equatable {
    public var id: String
    public var commandRegex: String
    public var action: PolicyAction
    public var reason: String

    public init(id: String, commandRegex: String, action: PolicyAction, reason: String) {
        self.id = id
        self.commandRegex = commandRegex
        self.action = action
        self.reason = reason
    }
}

public struct VerificationRule: Codable, Equatable {
    public var id: String
    public var targetPathRegex: String
    public var verifierCommand: [String]
    public var reason: String

    public init(id: String, targetPathRegex: String, verifierCommand: [String], reason: String) {
        self.id = id
        self.targetPathRegex = targetPathRegex
        self.verifierCommand = verifierCommand
        self.reason = reason
    }
}

public struct PolicyDocument: Codable, Equatable {
    public var formatVersion: Int
    public var policyID: String
    public var createdAt: String
    public var description: String
    public var profile: PolicyProfile
    public var memoryControl: MemoryControlMode
    public var monitoredExecutables: [String]
    public var governedPaths: [GovernedPathRule]
    public var governedCommands: [CommandRule]
    public var verificationRules: [VerificationRule]
    public var writableReferencePaths: [String]

    public init(
        formatVersion: Int = 2,
        policyID: String,
        createdAt: String,
        description: String,
        profile: PolicyProfile,
        memoryControl: MemoryControlMode = .disabled,
        monitoredExecutables: [String],
        governedPaths: [GovernedPathRule],
        governedCommands: [CommandRule],
        verificationRules: [VerificationRule],
        writableReferencePaths: [String] = []
    ) {
        self.formatVersion = formatVersion
        self.policyID = policyID
        self.createdAt = createdAt
        self.description = description
        self.profile = profile
        self.memoryControl = memoryControl
        self.monitoredExecutables = monitoredExecutables.sorted()
        self.governedPaths = governedPaths.sorted { $0.id < $1.id }
        self.governedCommands = governedCommands.sorted { $0.id < $1.id }
        self.verificationRules = verificationRules.sorted { $0.id < $1.id }
        self.writableReferencePaths = writableReferencePaths.sorted()
    }

    public func normalized() -> PolicyDocument {
        PolicyDocument(
            formatVersion: formatVersion,
            policyID: policyID,
            createdAt: createdAt,
            description: description,
            profile: profile,
            memoryControl: memoryControl,
            monitoredExecutables: monitoredExecutables.sorted(),
            governedPaths: governedPaths.sorted { $0.id < $1.id },
            governedCommands: governedCommands.sorted { $0.id < $1.id },
            verificationRules: verificationRules.sorted { $0.id < $1.id },
            writableReferencePaths: writableReferencePaths.sorted()
        )
    }
}

public struct ArtifactSignature: Codable, Equatable {
    public var algorithm: String
    public var publicKeyBase64: String
    public var signatureBase64: String
    public var signer: String
    public var keySource: String
    public var certificateDERBase64: String?

    public init(
        algorithm: String,
        publicKeyBase64: String,
        signatureBase64: String,
        signer: String,
        keySource: String,
        certificateDERBase64: String? = nil
    ) {
        self.algorithm = algorithm
        self.publicKeyBase64 = publicKeyBase64
        self.signatureBase64 = signatureBase64
        self.signer = signer
        self.keySource = keySource
        self.certificateDERBase64 = certificateDERBase64
    }
}

public typealias PolicySignature = ArtifactSignature

public struct SignedPolicyEnvelope: Codable, Equatable {
    public var policy: PolicyDocument
    public var signature: ArtifactSignature

    public init(policy: PolicyDocument, signature: ArtifactSignature) {
        self.policy = policy.normalized()
        self.signature = signature
    }
}

public struct BreakglassLease: Codable, Equatable {
    public var formatVersion: Int
    public var leaseID: String
    public var profile: PolicyProfile
    public var createdAt: String
    public var expiresAt: String
    public var pathPatterns: [String]
    public var operations: [GovernedOperation]
    public var bypassVerifier: Bool
    public var reason: String

    public init(
        formatVersion: Int = 1,
        leaseID: String,
        profile: PolicyProfile,
        createdAt: String,
        expiresAt: String,
        pathPatterns: [String],
        operations: [GovernedOperation],
        bypassVerifier: Bool,
        reason: String
    ) {
        self.formatVersion = formatVersion
        self.leaseID = leaseID
        self.profile = profile
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.pathPatterns = pathPatterns.sorted()
        self.operations = operations.sorted()
        self.bypassVerifier = bypassVerifier
        self.reason = reason
    }

    public func normalized() -> BreakglassLease {
        BreakglassLease(
            formatVersion: formatVersion,
            leaseID: leaseID,
            profile: profile,
            createdAt: createdAt,
            expiresAt: expiresAt,
            pathPatterns: pathPatterns.sorted(),
            operations: operations.sorted(),
            bypassVerifier: bypassVerifier,
            reason: reason
        )
    }
}

public struct SignedBreakglassLeaseEnvelope: Codable, Equatable {
    public var lease: BreakglassLease
    public var signature: ArtifactSignature

    public init(lease: BreakglassLease, signature: ArtifactSignature) {
        self.lease = lease.normalized()
        self.signature = signature
    }
}

public struct RuntimeEvent: Codable, Equatable {
    public var operation: GovernedOperation
    public var targetPath: String?
    public var sourcePath: String?
    public var processPath: String?
    public var argv: [String]?

    public init(
        operation: GovernedOperation,
        targetPath: String? = nil,
        sourcePath: String? = nil,
        processPath: String? = nil,
        argv: [String]? = nil
    ) {
        self.operation = operation
        self.targetPath = targetPath
        self.sourcePath = sourcePath
        self.processPath = processPath
        self.argv = argv
    }
}

public struct PolicyDecision: Codable, Equatable {
    public var action: PolicyAction
    public var reason: String
    public var matchedRuleID: String?
    public var matchedLeaseID: String?
    public var detail: String?
    public var verifierBypassed: Bool

    public init(
        action: PolicyAction,
        reason: String,
        matchedRuleID: String? = nil,
        matchedLeaseID: String? = nil,
        detail: String? = nil,
        verifierBypassed: Bool = false
    ) {
        self.action = action
        self.reason = reason
        self.matchedRuleID = matchedRuleID
        self.matchedLeaseID = matchedLeaseID
        self.detail = detail
        self.verifierBypassed = verifierBypassed
    }
}

public enum VerificationOutcome: Equatable {
    case allow(detail: String = "")
    case deny(detail: String = "")
    case infrastructureFailure(detail: String)
}

public enum HealthStatus: String, Codable, Comparable {
    case pass
    case warn
    case fail

    public static func < (lhs: HealthStatus, rhs: HealthStatus) -> Bool {
        let rank: [HealthStatus: Int] = [.pass: 0, .warn: 1, .fail: 2]
        return (rank[lhs] ?? 0) < (rank[rhs] ?? 0)
    }
}

public struct DoctorCheck: Codable, Equatable {
    public var id: String
    public var status: HealthStatus
    public var summary: String
    public var detail: String?
    public var remediation: String?

    public init(
        id: String,
        status: HealthStatus,
        summary: String,
        detail: String? = nil,
        remediation: String? = nil
    ) {
        self.id = id
        self.status = status
        self.summary = summary
        self.detail = detail
        self.remediation = remediation
    }
}

public enum ActivationState: String, Codable {
    case inactive
    case policyInstalled = "policy_installed"
    case activationRequested = "activation_requested"
    case deactivationRequested = "deactivation_requested"
    case pendingApproval = "pending_approval"
    case active
    case broken
}

public struct DoctorReport: Codable, Equatable {
    public var generatedAt: String
    public var overallStatus: HealthStatus
    public var runtimeRoot: String
    public var hostAppPath: String
    public var checks: [DoctorCheck]

    public init(
        generatedAt: String,
        overallStatus: HealthStatus,
        runtimeRoot: String,
        hostAppPath: String,
        checks: [DoctorCheck]
    ) {
        self.generatedAt = generatedAt
        self.overallStatus = overallStatus
        self.runtimeRoot = runtimeRoot
        self.hostAppPath = hostAppPath
        self.checks = checks
    }
}

public struct StatusReport: Codable, Equatable {
    public var generatedAt: String
    public var activationState: ActivationState
    public var runtimeRoot: String
    public var hostAppPath: String
    public var signedPolicyPath: String?
    public var loadedProfile: PolicyProfile?
    public var memoryControl: MemoryControlMode?
    public var policyFingerprint: String?
    public var yubikeyIdentityCommonName: String?
    public var activeLeaseCount: Int
    public var checks: [DoctorCheck]

    public init(
        generatedAt: String,
        activationState: ActivationState,
        runtimeRoot: String,
        hostAppPath: String,
        signedPolicyPath: String? = nil,
        loadedProfile: PolicyProfile? = nil,
        memoryControl: MemoryControlMode? = nil,
        policyFingerprint: String? = nil,
        yubikeyIdentityCommonName: String? = nil,
        activeLeaseCount: Int = 0,
        checks: [DoctorCheck] = []
    ) {
        self.generatedAt = generatedAt
        self.activationState = activationState
        self.runtimeRoot = runtimeRoot
        self.hostAppPath = hostAppPath
        self.signedPolicyPath = signedPolicyPath
        self.loadedProfile = loadedProfile
        self.memoryControl = memoryControl
        self.policyFingerprint = policyFingerprint
        self.yubikeyIdentityCommonName = yubikeyIdentityCommonName
        self.activeLeaseCount = activeLeaseCount
        self.checks = checks
    }
}

public struct SigningIdentitySummary: Codable, Equatable {
    public var commonName: String
    public var keySource: String
    public var tokenID: String?
    public var isTokenBacked: Bool
    public var certificatePresent: Bool

    public init(
        commonName: String,
        keySource: String,
        tokenID: String?,
        isTokenBacked: Bool,
        certificatePresent: Bool
    ) {
        self.commonName = commonName
        self.keySource = keySource
        self.tokenID = tokenID
        self.isTokenBacked = isTokenBacked
        self.certificatePresent = certificatePresent
    }
}

public struct SigningIdentityDoctorReport: Codable, Equatable {
    public var identity: SigningIdentitySummary
    public var signingChallengePassed: Bool
    public var certificateTrustStatus: HealthStatus
    public var certificateTrustDetail: String?

    public init(
        identity: SigningIdentitySummary,
        signingChallengePassed: Bool,
        certificateTrustStatus: HealthStatus,
        certificateTrustDetail: String? = nil
    ) {
        self.identity = identity
        self.signingChallengePassed = signingChallengePassed
        self.certificateTrustStatus = certificateTrustStatus
        self.certificateTrustDetail = certificateTrustDetail
    }
}

public struct CassDeploymentConfig: Codable, Equatable, Sendable {
    public var hostAppPath: String
    public var hostAppBundleIdentifier: String
    public var systemExtensionBundleIdentifier: String

    public init(
        hostAppPath: String,
        hostAppBundleIdentifier: String,
        systemExtensionBundleIdentifier: String
    ) {
        self.hostAppPath = hostAppPath
        self.hostAppBundleIdentifier = hostAppBundleIdentifier
        self.systemExtensionBundleIdentifier = systemExtensionBundleIdentifier
    }

    public static let production = CassDeploymentConfig(
        hostAppPath: "/Applications/CASS Control.app",
        hostAppBundleIdentifier: "com.orxaq.cass.control",
        systemExtensionBundleIdentifier: "com.orxaq.cass.enforcer"
    )
}

public struct CassRuntimeLayout: Codable, Equatable {
    public var rootDirectory: String

    public init(rootDirectory: String) {
        self.rootDirectory = CassRuntimeLayout.normalize(rootDirectory)
    }

    public var policiesDirectory: String {
        "\(rootDirectory)/policies"
    }

    public var leasesDirectory: String {
        "\(rootDirectory)/leases"
    }

    public var auditDirectory: String {
        "\(rootDirectory)/audit"
    }

    public var statusDirectory: String {
        "\(rootDirectory)/status"
    }

    public var activePolicyPath: String {
        "\(policiesDirectory)/active-policy.signed.json"
    }

    public var auditLogPath: String {
        "\(auditDirectory)/audit.jsonl"
    }

    public var statusPath: String {
        "\(statusDirectory)/current.json"
    }

    public var activationRequestPath: String {
        "\(statusDirectory)/activation-request.json"
    }

    public static func production(rootDirectory: String = "/Library/Application Support/com.orxaq.cass") -> CassRuntimeLayout {
        CassRuntimeLayout(rootDirectory: rootDirectory)
    }

    private static func normalize(_ path: String) -> String {
        URL(fileURLWithPath: path).standardized.path
    }
}

public struct ActivationRequest: Codable, Equatable {
    public var requestedAt: String
    public var profile: PolicyProfile
    public var signedPolicyPath: String
    public var runtimeRoot: String
    public var hostAppBundleIdentifier: String
    public var systemExtensionBundleIdentifier: String

    public init(
        requestedAt: String,
        profile: PolicyProfile,
        signedPolicyPath: String,
        runtimeRoot: String,
        hostAppBundleIdentifier: String,
        systemExtensionBundleIdentifier: String
    ) {
        self.requestedAt = requestedAt
        self.profile = profile
        self.signedPolicyPath = signedPolicyPath
        self.runtimeRoot = runtimeRoot
        self.hostAppBundleIdentifier = hostAppBundleIdentifier
        self.systemExtensionBundleIdentifier = systemExtensionBundleIdentifier
    }
}

public struct LeaseRevocationRecord: Codable, Equatable {
    public var leaseID: String
    public var revokedAt: String
    public var reason: String

    public init(leaseID: String, revokedAt: String, reason: String) {
        self.leaseID = leaseID
        self.revokedAt = revokedAt
        self.reason = reason
    }
}

public struct StoredLeaseRecord: Codable, Equatable {
    public var envelope: SignedBreakglassLeaseEnvelope
    public var revokedAt: String?
    public var active: Bool

    public init(envelope: SignedBreakglassLeaseEnvelope, revokedAt: String?, active: Bool) {
        self.envelope = envelope
        self.revokedAt = revokedAt
        self.active = active
    }
}

public struct AuditRecord: Codable, Equatable {
    public var recordedAt: String
    public var category: String
    public var leaseID: String?
    public var ruleID: String?
    public var outcome: String
    public var detail: String?

    public init(
        recordedAt: String,
        category: String,
        leaseID: String? = nil,
        ruleID: String? = nil,
        outcome: String,
        detail: String? = nil
    ) {
        self.recordedAt = recordedAt
        self.category = category
        self.leaseID = leaseID
        self.ruleID = ruleID
        self.outcome = outcome
        self.detail = detail
    }
}
