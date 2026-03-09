import CassPolicyCore
import Darwin
import EndpointSecurity
import Foundation
import Security

public final class EndpointSecurityDaemon {
    private let envelope: SignedPolicyEnvelope
    private let engine: PolicyEngine
    private let verifier: VerificationRunner
    private let processTracker = ProcessTracker()
    private let layout: CassRuntimeLayout
    private let deploymentConfig: CassDeploymentConfig
    private let leaseStore: LeaseStore
    private let auditLogger: AuditLogger

    public init(
        envelope: SignedPolicyEnvelope,
        layout: CassRuntimeLayout = .production(),
        deploymentConfig: CassDeploymentConfig = .production,
        verifier: VerificationRunner = ProcessVerificationRunner(),
        leaseStore: LeaseStore? = nil,
        auditLogger: AuditLogger? = nil
    ) {
        self.envelope = envelope
        self.engine = PolicyEngine(policy: envelope.policy)
        self.verifier = verifier
        self.layout = layout
        self.deploymentConfig = deploymentConfig
        self.leaseStore = leaseStore ?? LeaseStore(layout: layout)
        self.auditLogger = auditLogger ?? AuditLogger(layout: layout)
    }

    public func doctor() -> DoctorReport {
        var checks = [DoctorCheck]()

        checks.append(
            DoctorCheck(
                id: "root",
                status: geteuid() == 0 ? .pass : .fail,
                summary: geteuid() == 0 ? "Daemon is running as root." : "Daemon is not running as root.",
                remediation: "Run the Endpoint Security service as root via the signed host app / system extension deployment path."
            )
        )

        do {
            try PolicySigner.verify(envelope: envelope)
            checks.append(
                DoctorCheck(
                    id: "signed-policy",
                    status: .pass,
                    summary: "Signed policy envelope verified."
                )
            )
        } catch {
            checks.append(
                DoctorCheck(
                    id: "signed-policy",
                    status: .fail,
                    summary: "Signed policy envelope is invalid.",
                    detail: error.localizedDescription,
                    remediation: "Re-sign the policy with the YubiKey-backed identity before activating enforcement."
                )
            )
        }

        do {
            try leaseStore.validate()
            checks.append(
                DoctorCheck(
                    id: "lease-store",
                    status: .pass,
                    summary: "Lease store is readable and valid."
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

        let esClientResult = probeClient()
        checks.append(
            DoctorCheck(
                id: "endpoint-security-client",
                status: esClientResult == "success" ? .pass : .fail,
                summary: esClientResult == "success" ? "Endpoint Security client probe succeeded." : "Endpoint Security client probe failed.",
                detail: esClientResult,
                remediation: "Confirm the live system extension is signed with the managed Endpoint Security entitlement and approved on this Mac."
            )
        )

        return DoctorReport(
            generatedAt: CassTime.string(),
            overallStatus: checks.map(\.status).max() ?? .pass,
            runtimeRoot: layout.rootDirectory,
            hostAppPath: deploymentConfig.hostAppPath,
            checks: checks
        )
    }

    public func run() throws {
        try PolicySigner.verify(envelope: envelope)
        try RuntimeSupport.ensureRuntimeDirectories(layout: layout)
        try leaseStore.validate()

        var client: OpaquePointer?
        let createResult = es_new_client(&client) { [weak self] clientPtr, messagePtr in
            guard let self else {
                return
            }
            self.handle(client: clientPtr, message: messagePtr)
        }
        guard createResult == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
            throw CassPolicyError.verificationFailed("Unable to create ES client: \(describe(createResult)).")
        }

        var subscribedEvents: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_AUTH_OPEN,
            ES_EVENT_TYPE_AUTH_CREATE,
            ES_EVENT_TYPE_AUTH_RENAME,
            ES_EVENT_TYPE_AUTH_UNLINK,
            ES_EVENT_TYPE_AUTH_SETFLAGS,
            ES_EVENT_TYPE_AUTH_SETMODE,
            ES_EVENT_TYPE_AUTH_SETEXTATTR,
            ES_EVENT_TYPE_AUTH_TRUNCATE,
            ES_EVENT_TYPE_AUTH_CLONE,
            ES_EVENT_TYPE_AUTH_COPYFILE,
            ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
            ES_EVENT_TYPE_NOTIFY_FORK,
        ]
        let subscribeResult = es_subscribe(client, &subscribedEvents, UInt32(subscribedEvents.count))
        guard subscribeResult == ES_RETURN_SUCCESS else {
            _ = es_delete_client(client)
            throw CassPolicyError.verificationFailed("Unable to subscribe to Endpoint Security events.")
        }
        dispatchMain()
    }

    private func probeClient() -> String {
        var client: OpaquePointer?
        let result = es_new_client(&client) { _, _ in }
        if result == ES_NEW_CLIENT_RESULT_SUCCESS, let client {
            _ = es_delete_client(client)
        }
        return describe(result)
    }

    private func handle(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
        let eventType = message.pointee.event_type
        if eventType == ES_EVENT_TYPE_NOTIFY_FORK {
            handleFork(message)
            return
        }

        if eventType == ES_EVENT_TYPE_AUTH_EXEC {
            markTrackedExec(message)
        }

        guard isTracked(message.pointee.process.pointee) else {
            respondAllow(client: client, message: message)
            return
        }

        guard let runtimeEvent = runtimeEvent(from: message) else {
            respondAllow(client: client, message: message)
            return
        }

        do {
            let activeLeases = try leaseStore.activeLeases(for: envelope.policy.profile)
            let decision = try engine.decide(event: runtimeEvent, verifier: verifier, activeLeases: activeLeases)

            if let matchedLeaseID = decision.matchedLeaseID {
                try auditLogger.append(
                    AuditRecord(
                        recordedAt: CassTime.string(),
                        category: "lease-use",
                        leaseID: matchedLeaseID,
                        ruleID: decision.matchedRuleID,
                        outcome: decision.action.rawValue,
                        detail: decision.detail
                    )
                )
            } else if decision.action == .deny {
                try? auditLogger.append(
                    AuditRecord(
                        recordedAt: CassTime.string(),
                        category: "deny",
                        ruleID: decision.matchedRuleID,
                        outcome: decision.action.rawValue,
                        detail: decision.detail
                    )
                )
            }

            switch decision.action {
            case .allow:
                respondAllow(client: client, message: message)
            case .deny:
                respondDeny(client: client, message: message)
            }
        } catch {
            respondDeny(client: client, message: message)
        }
    }

    private func handleFork(_ message: UnsafePointer<es_message_t>) {
        let parent = message.pointee.process.pointee
        let child = message.pointee.event.fork.child.pointee
        if isTracked(parent) {
            processTracker.insert(child.audit_token)
        }
    }

    private func markTrackedExec(_ message: UnsafePointer<es_message_t>) {
        let source = message.pointee.process.pointee
        let target = message.pointee.event.exec.target.pointee
        if isTracked(source) || matchesMonitoredExecutable(path(from: target.executable.pointee.path)) {
            processTracker.insert(target.audit_token)
        }
    }

    private func isTracked(_ process: es_process_t) -> Bool {
        if matchesMonitoredExecutable(path(from: process.executable.pointee.path)) {
            processTracker.insert(process.audit_token)
            return true
        }
        return processTracker.contains(process.audit_token)
            || processTracker.contains(process.parent_audit_token)
            || processTracker.contains(process.responsible_audit_token)
    }

    private func matchesMonitoredExecutable(_ executablePath: String) -> Bool {
        envelope.policy.monitoredExecutables.contains { pattern in
            PathMatcher.matches(glob: pattern, path: executablePath)
        }
    }

    private func runtimeEvent(from message: UnsafePointer<es_message_t>) -> RuntimeEvent? {
        let processPath = path(from: message.pointee.process.pointee.executable.pointee.path)
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            let execEvent = message.pointee.event.exec
            return RuntimeEvent(
                operation: .exec,
                targetPath: path(from: execEvent.target.pointee.executable.pointee.path),
                processPath: processPath,
                argv: arguments(from: execEvent)
            )

        case ES_EVENT_TYPE_AUTH_OPEN:
            let openEvent = message.pointee.event.open
            guard (openEvent.fflag & FWRITE) != 0 else {
                return nil
            }
            return RuntimeEvent(
                operation: .openWrite,
                targetPath: path(from: openEvent.file.pointee.path),
                processPath: processPath
            )

        case ES_EVENT_TYPE_AUTH_CREATE:
            let createEvent = message.pointee.event.create
            let targetPath: String
            switch createEvent.destination_type {
            case ES_DESTINATION_TYPE_EXISTING_FILE:
                targetPath = path(from: createEvent.destination.existing_file.pointee.path)
            default:
                targetPath = join(directory: path(from: createEvent.destination.new_path.dir.pointee.path), name: string(from: createEvent.destination.new_path.filename))
            }
            return RuntimeEvent(operation: .create, targetPath: targetPath, processPath: processPath)

        case ES_EVENT_TYPE_AUTH_RENAME:
            let renameEvent = message.pointee.event.rename
            let targetPath: String
            switch renameEvent.destination_type {
            case ES_DESTINATION_TYPE_EXISTING_FILE:
                targetPath = path(from: renameEvent.destination.existing_file.pointee.path)
            default:
                targetPath = join(directory: path(from: renameEvent.destination.new_path.dir.pointee.path), name: string(from: renameEvent.destination.new_path.filename))
            }
            return RuntimeEvent(
                operation: .rename,
                targetPath: targetPath,
                sourcePath: path(from: renameEvent.source.pointee.path),
                processPath: processPath
            )

        case ES_EVENT_TYPE_AUTH_UNLINK:
            return RuntimeEvent(
                operation: .unlink,
                targetPath: path(from: message.pointee.event.unlink.target.pointee.path),
                processPath: processPath
            )

        case ES_EVENT_TYPE_AUTH_SETFLAGS:
            return RuntimeEvent(
                operation: .setFlags,
                targetPath: path(from: message.pointee.event.setflags.target.pointee.path),
                processPath: processPath
            )

        case ES_EVENT_TYPE_AUTH_SETMODE:
            return RuntimeEvent(
                operation: .setMode,
                targetPath: path(from: message.pointee.event.setmode.target.pointee.path),
                processPath: processPath
            )

        case ES_EVENT_TYPE_AUTH_SETEXTATTR:
            return RuntimeEvent(
                operation: .setExtAttr,
                targetPath: path(from: message.pointee.event.setextattr.target.pointee.path),
                processPath: processPath
            )

        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            return RuntimeEvent(
                operation: .truncate,
                targetPath: path(from: message.pointee.event.truncate.target.pointee.path),
                processPath: processPath
            )

        case ES_EVENT_TYPE_AUTH_CLONE:
            let event = message.pointee.event.clone
            return RuntimeEvent(
                operation: .clone,
                targetPath: join(directory: path(from: event.target_dir.pointee.path), name: string(from: event.target_name)),
                sourcePath: path(from: event.source.pointee.path),
                processPath: processPath
            )

        case ES_EVENT_TYPE_AUTH_COPYFILE:
            let event = message.pointee.event.copyfile
            return RuntimeEvent(
                operation: .copyFile,
                targetPath: join(directory: path(from: event.target_dir.pointee.path), name: string(from: event.target_name)),
                sourcePath: path(from: event.source.pointee.path),
                processPath: processPath
            )

        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
            let event = message.pointee.event.exchangedata
            return RuntimeEvent(
                operation: .exchangeData,
                targetPath: path(from: event.file2.pointee.path),
                sourcePath: path(from: event.file1.pointee.path),
                processPath: processPath
            )

        default:
            return nil
        }
    }

    private func arguments(from execEvent: es_event_exec_t) -> [String] {
        var mutableExecEvent = execEvent
        let count = withUnsafePointer(to: &mutableExecEvent) { pointer in
            es_exec_arg_count(pointer)
        }
        if count == 0 {
            return []
        }
        return (0..<count).map { index in
            withUnsafePointer(to: &mutableExecEvent) { pointer in
                string(from: es_exec_arg(pointer, index))
            }
        }
    }

    private func respondAllow(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
        if message.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN {
            _ = es_respond_flags_result(client, message, UInt32.max, false)
        } else {
            _ = es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
        }
    }

    private func respondDeny(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
        if message.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN {
            _ = es_respond_flags_result(client, message, 0, false)
        } else {
            _ = es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
        }
    }

    private func describe(_ result: es_new_client_result_t) -> String {
        switch result {
        case ES_NEW_CLIENT_RESULT_SUCCESS:
            return "success"
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            return "invalid-argument"
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            return "internal"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return "not-entitled"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return "not-permitted"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            return "not-privileged"
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            return "too-many-clients"
        default:
            return "unknown"
        }
    }

    private func string(from token: es_string_token_t) -> String {
        let data = Data(bytes: token.data, count: token.length)
        return String(data: data, encoding: .utf8) ?? ""
    }

    private func path(from token: es_string_token_t) -> String {
        string(from: token)
    }

    private func join(directory: String, name: String) -> String {
        URL(fileURLWithPath: directory).appendingPathComponent(name).path
    }
}

private final class ProcessTracker {
    private var tracked: Set<String> = []
    private let lock = NSLock()

    func insert(_ token: audit_token_t) {
        lock.lock()
        tracked.insert(key(for: token))
        lock.unlock()
    }

    func contains(_ token: audit_token_t) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return tracked.contains(key(for: token))
    }

    private func key(for token: audit_token_t) -> String {
        "\(cass_audit_token_to_pid(token)):\(cass_audit_token_to_pidversion(token))"
    }
}

@_silgen_name("audit_token_to_pid")
private func cass_audit_token_to_pid(_ token: audit_token_t) -> pid_t

@_silgen_name("audit_token_to_pidversion")
private func cass_audit_token_to_pidversion(_ token: audit_token_t) -> Int32
