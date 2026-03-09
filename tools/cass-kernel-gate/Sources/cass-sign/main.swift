import CassPolicyCore
import Foundation

enum CassSignCLI {
    static func main() throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard let command = arguments.first else {
            throw CassPolicyError.invalidCommand("Expected subcommand: generate-se-key or sign")
        }
        switch command {
        case "generate-se-key":
            let label = try CLIHelpers.value(after: "--label", in: arguments)
            let publicKeyBase64 = try PolicySigner.generateSecureEnclaveKey(label: label)
            try CLIHelpers.printJSON([
                "status": "ok",
                "label": label,
                "public_key_base64": publicKeyBase64,
            ])

        case "generate-keychain-key":
            let label = try CLIHelpers.value(after: "--label", in: arguments)
            let publicKeyBase64 = try PolicySigner.generateKeychainKey(label: label)
            try CLIHelpers.printJSON([
                "status": "ok",
                "label": label,
                "public_key_base64": publicKeyBase64,
            ])

        case "sign":
            let policyPath = try CLIHelpers.value(after: "--policy", in: arguments)
            let outputPath = try CLIHelpers.value(after: "--output", in: arguments)
            let policy = try PolicyLoader.loadPolicy(at: policyPath)
            let approval = ApprovalMode(rawValue: CLIHelpers.optionalValue(after: "--approval", in: arguments) ?? "none")
                ?? .none
            try ApprovalGate.authorize(
                mode: approval,
                reason: "Approve signing the CASS policy envelope for Claude Code enforcement."
            )
            let material: SigningKeyMaterial
            if let label = CLIHelpers.optionalValue(after: "--key-label", in: arguments) {
                material = try PolicySigner.loadKey(label: label)
            } else if let commonName = CLIHelpers.optionalValue(after: "--identity-common-name", in: arguments) {
                material = try PolicySigner.loadIdentity(commonName: commonName)
            } else {
                throw CassPolicyError.missingArgument("--key-label or --identity-common-name")
            }
            let envelope = try PolicySigner.sign(policy: policy, using: material)
            try PolicyLoader.writeSignedPolicy(envelope, to: outputPath)
            try CLIHelpers.printJSON([
                "status": "ok",
                "output": outputPath,
                "signer": envelope.signature.signer,
                "key_source": envelope.signature.keySource,
            ])

        default:
            throw CassPolicyError.invalidCommand(command)
        }
    }
}

do {
    try CassSignCLI.main()
} catch {
    fputs("cass-sign: \(error.localizedDescription)\n", stderr)
    exit(1)
}
