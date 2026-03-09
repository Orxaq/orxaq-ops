// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "CassKernelGate",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "CassPolicyCore", targets: ["CassPolicyCore"]),
        .library(name: "CassEndpointSecuritySupport", targets: ["CassEndpointSecuritySupport"]),
        .executable(name: "cass-policy", targets: ["cass-policy"]),
        .executable(name: "cassctl", targets: ["cassctl"]),
        .executable(name: "cass-sign", targets: ["cass-sign"]),
        .executable(name: "cass-verify-policy", targets: ["cass-verify-policy"]),
        .executable(name: "cass-daemon", targets: ["cass-daemon"]),
    ],
    targets: [
        .target(
            name: "CassPolicyCore",
            linkerSettings: [
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("Security"),
            ]
        ),
        .target(
            name: "CassEndpointSecuritySupport",
            dependencies: ["CassPolicyCore"],
            linkerSettings: [
                .linkedLibrary("EndpointSecurity"),
                .linkedFramework("Security"),
                .linkedLibrary("bsm"),
            ]
        ),
        .executableTarget(
            name: "cass-policy",
            dependencies: ["CassPolicyCore"]
        ),
        .executableTarget(
            name: "cassctl",
            dependencies: ["CassPolicyCore", "CassEndpointSecuritySupport"]
        ),
        .executableTarget(
            name: "cass-sign",
            dependencies: ["CassPolicyCore"]
        ),
        .executableTarget(
            name: "cass-verify-policy",
            dependencies: ["CassPolicyCore"]
        ),
        .executableTarget(
            name: "cass-daemon",
            dependencies: ["CassPolicyCore", "CassEndpointSecuritySupport"]
        ),
        .testTarget(
            name: "CassPolicyCoreTests",
            dependencies: ["CassPolicyCore"],
            linkerSettings: [
                .linkedFramework("Security"),
            ]
        ),
    ]
)
