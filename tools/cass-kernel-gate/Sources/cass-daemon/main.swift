import CassEndpointSecuritySupport
import CassPolicyCore
import Foundation

enum CassDaemonCLI {
    static func main() throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard let command = arguments.first else {
            throw CassPolicyError.invalidCommand("Expected subcommand: doctor, dry-run, or run")
        }

        let runtimeRoot = CLIHelpers.optionalValue(after: "--runtime-root", in: arguments)
            ?? CassRuntimeLayout.production().rootDirectory
        let layout = CassRuntimeLayout(rootDirectory: runtimeRoot)
        let deploymentConfig = CassDeploymentConfig(
            hostAppPath: CLIHelpers.optionalValue(after: "--host-app-path", in: arguments) ?? CassDeploymentConfig.production.hostAppPath,
            hostAppBundleIdentifier: CLIHelpers.optionalValue(after: "--host-app-bundle-id", in: arguments) ?? CassDeploymentConfig.production.hostAppBundleIdentifier,
            systemExtensionBundleIdentifier: CLIHelpers.optionalValue(after: "--extension-bundle-id", in: arguments) ?? CassDeploymentConfig.production.systemExtensionBundleIdentifier
        )
        let signedPolicyPath = try CLIHelpers.value(after: "--signed-policy", in: arguments)
        let envelope = try PolicyLoader.loadSignedPolicy(at: signedPolicyPath)
        let daemon = EndpointSecurityDaemon(
            envelope: envelope,
            layout: layout,
            deploymentConfig: deploymentConfig
        )

        switch command {
        case "doctor":
            try CLIHelpers.printJSON(daemon.doctor())

        case "dry-run":
            let eventPath = try CLIHelpers.value(after: "--event", in: arguments)
            let data = try Data(contentsOf: URL(fileURLWithPath: eventPath))
            let event = try JSONDecoder().decode(RuntimeEvent.self, from: data)
            let engine = PolicyEngine(policy: envelope.policy)
            let leaseStore = LeaseStore(layout: layout)
            let activeLeases = try leaseStore.activeLeases(for: envelope.policy.profile)
            let decision = try engine.decide(event: event, verifier: ProcessVerificationRunner(), activeLeases: activeLeases)
            try CLIHelpers.printJSON(decision)

        case "run":
            try daemon.run()

        default:
            throw CassPolicyError.invalidCommand(command)
        }
    }
}

do {
    try CassDaemonCLI.main()
} catch {
    fputs("cass-daemon: \(error.localizedDescription)\n", stderr)
    exit(1)
}
