import CassPolicyCore
import Foundation

enum CassVerifyPolicyCLI {
    static func main() throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        let signedPolicyPath = try CLIHelpers.value(after: "--signed-policy", in: arguments)
        let envelope = try PolicyLoader.loadSignedPolicy(at: signedPolicyPath)
        try PolicySigner.verify(envelope: envelope)
        try CLIHelpers.printJSON([
            "status": "ok",
            "signed_policy": signedPolicyPath,
            "policy_id": envelope.policy.policyID,
            "signer": envelope.signature.signer,
            "key_source": envelope.signature.keySource,
        ])
    }
}

do {
    try CassVerifyPolicyCLI.main()
} catch {
    fputs("cass-verify-policy: \(error.localizedDescription)\n", stderr)
    exit(1)
}
