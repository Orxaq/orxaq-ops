import CassPolicyCore
import Foundation

enum CassPolicyCLI {
    static func main() throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard let command = arguments.first else {
            throw CassPolicyError.invalidCommand("Expected subcommand: init-claude")
        }

        switch command {
        case "init-claude":
            let home = try CLIHelpers.value(after: "--home", in: arguments)
            let repo = try CLIHelpers.value(after: "--repo", in: arguments)
            let output = try CLIHelpers.value(after: "--output", in: arguments)
            let verifier = try CLIHelpers.value(after: "--verifier", in: arguments)
            let profileRaw = try CLIHelpers.value(after: "--profile", in: arguments)
            guard let profile = PolicyProfile(rawValue: profileRaw) else {
                throw CassPolicyError.invalidPolicy("Unknown profile '\(profileRaw)'.")
            }
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
            try PolicyLoader.writePolicy(policy, to: output)
            try CLIHelpers.printJSON([
                "status": "ok",
                "output": output,
                "policy_id": policy.policyID,
                "profile": policy.profile.rawValue,
                "memory_control": policy.memoryControl.rawValue,
            ])

        default:
            throw CassPolicyError.invalidCommand(command)
        }
    }
}

do {
    try CassPolicyCLI.main()
} catch {
    fputs("cass-policy: \(error.localizedDescription)\n", stderr)
    exit(1)
}
