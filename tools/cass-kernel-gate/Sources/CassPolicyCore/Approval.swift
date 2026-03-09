import Foundation
import LocalAuthentication

public enum ApprovalMode: String {
    case none
    case companion
    case biometricsOrCompanion
}

public enum ApprovalGate {
    public static func authorize(mode: ApprovalMode, reason: String) throws {
        switch mode {
        case .none:
            return
        case .companion:
            guard #available(macOS 15.0, *) else {
                throw CassPolicyError.signingFailed("Companion authentication requires macOS 15.0 or later.")
            }
            try evaluate(policy: .deviceOwnerAuthenticationWithCompanion, reason: reason)
        case .biometricsOrCompanion:
            guard #available(macOS 15.0, *) else {
                throw CassPolicyError.signingFailed("Companion authentication requires macOS 15.0 or later.")
            }
            try evaluate(policy: .deviceOwnerAuthenticationWithBiometricsOrCompanion, reason: reason)
        }
    }

    private static func evaluate(policy: LAPolicy, reason: String) throws {
        guard #available(macOS 15.0, *) else {
            throw CassPolicyError.signingFailed("Companion authentication requires macOS 15.0 or later.")
        }
        let context = LAContext()
        var capabilityError: NSError?
        guard context.canEvaluatePolicy(policy, error: &capabilityError) else {
            throw CassPolicyError.signingFailed(capabilityError?.localizedDescription ?? "Companion authentication is not available.")
        }

        let semaphore = DispatchSemaphore(value: 0)
        let errorBox = ApprovalErrorBox()
        context.evaluatePolicy(policy, localizedReason: reason) { success, error in
            if !success {
                errorBox.error = error ?? CassPolicyError.signingFailed("Companion approval failed.")
            }
            semaphore.signal()
        }
        semaphore.wait()
        if let approvalError = errorBox.error {
            throw CassPolicyError.signingFailed(approvalError.localizedDescription)
        }
    }
}

private final class ApprovalErrorBox: @unchecked Sendable {
    var error: Error?
}
