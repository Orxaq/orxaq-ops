import CassEndpointSecuritySupport
import CassPolicyCore
import Foundation

do {
    let runtimeRoot = ProcessInfo.processInfo.environment["CASS_RUNTIME_ROOT"]
        ?? CassRuntimeLayout.production().rootDirectory
    let layout = CassRuntimeLayout(rootDirectory: runtimeRoot)
    let envelope = try PolicyLoader.loadSignedPolicy(at: layout.activePolicyPath)
    let daemon = EndpointSecurityDaemon(
        envelope: envelope,
        layout: layout,
        deploymentConfig: .production
    )
    try daemon.run()
} catch {
    fputs("CASSEnforcer failed: \(error.localizedDescription)\n", stderr)
    exit(1)
}
