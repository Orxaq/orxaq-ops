import AppKit
import CassPolicyCore
import Foundation
import SystemExtensions

final class SystemExtensionCoordinator: NSObject, OSSystemExtensionRequestDelegate {
    private enum PendingOperation {
        case activate
        case deactivate
    }

    private var activationRequest: ActivationRequest?
    private var pendingOperation: PendingOperation = .activate

    func handleLaunch(arguments: [String]) {
        do {
            if let index = arguments.firstIndex(of: "--cass-activate-request"), index + 1 < arguments.count {
                let requestPath = arguments[index + 1]
                let request = try PolicyLoader.loadJSON(ActivationRequest.self, at: requestPath)
                activationRequest = request
                pendingOperation = .activate
                try submitActivation(request)
                return
            }

            if let index = arguments.firstIndex(of: "--cass-deactivate-request"), index + 1 < arguments.count {
                let requestPath = arguments[index + 1]
                let request = try PolicyLoader.loadJSON(ActivationRequest.self, at: requestPath)
                activationRequest = request
                pendingOperation = .deactivate
                submitDeactivation(request)
                return
            }

            NSApp.terminate(nil)
        } catch {
            fputs("CASS Control activation failed: \(error.localizedDescription)\n", stderr)
            NSApp.terminate(nil)
        }
    }

    private func submitActivation(_ request: ActivationRequest) throws {
        let systemRequest = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: request.systemExtensionBundleIdentifier,
            queue: .main
        )
        systemRequest.delegate = self
        OSSystemExtensionManager.shared.submitRequest(systemRequest)
        try updateStatus(state: .pendingApproval)
    }

    private func submitDeactivation(_ request: ActivationRequest) {
        let systemRequest = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: request.systemExtensionBundleIdentifier,
            queue: .main
        )
        systemRequest.delegate = self
        OSSystemExtensionManager.shared.submitRequest(systemRequest)
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        try? updateStatus(state: .pendingApproval)
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch pendingOperation {
        case .activate:
            try? updateStatus(state: .active)
        case .deactivate:
            try? updateStatus(state: .inactive)
        }
        NSApp.terminate(nil)
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        fputs("System extension request failed: \(error.localizedDescription)\n", stderr)
        try? updateStatus(state: .broken)
        NSApp.terminate(nil)
    }

    private func updateStatus(state: ActivationState) throws {
        guard let activationRequest else {
            return
        }
        let layout = CassRuntimeLayout(rootDirectory: activationRequest.runtimeRoot)
        let current = (try? PolicyLoader.loadJSON(StatusReport.self, at: layout.statusPath))
            ?? StatusReport(
                generatedAt: CassTime.string(),
                activationState: state,
                runtimeRoot: layout.rootDirectory,
                hostAppPath: CassDeploymentConfig.production.hostAppPath,
                signedPolicyPath: activationRequest.signedPolicyPath,
                loadedProfile: activationRequest.profile
            )

        let updated = StatusReport(
            generatedAt: CassTime.string(),
            activationState: state,
            runtimeRoot: current.runtimeRoot,
            hostAppPath: current.hostAppPath,
            signedPolicyPath: current.signedPolicyPath,
            loadedProfile: current.loadedProfile,
            memoryControl: current.memoryControl,
            policyFingerprint: current.policyFingerprint,
            yubikeyIdentityCommonName: current.yubikeyIdentityCommonName,
            activeLeaseCount: current.activeLeaseCount,
            checks: current.checks
        )
        try PolicyLoader.writeJSON(updated, to: layout.statusPath)
        if state == .inactive {
            try? FileManager.default.removeItem(atPath: layout.activationRequestPath)
        }
    }
}
