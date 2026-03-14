// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SwiftTunnelMacOSSupport",
    platforms: [
        .macOS(.v15),
    ],
    products: [
        .library(
            name: "SwiftTunnelMacOSShared",
            targets: ["SwiftTunnelMacOSShared"]
        ),
        .library(
            name: "SwiftTunnelTransparentProxyProvider",
            targets: ["SwiftTunnelTransparentProxyProvider"]
        ),
        .executable(
            name: "swifttunnel-macos-helper",
            targets: ["swifttunnel-macos-helper"]
        ),
    ],
    targets: [
        .target(
            name: "SwiftTunnelMacOSShared",
            linkerSettings: [
                .linkedFramework("Network"),
                .linkedFramework("NetworkExtension"),
            ]
        ),
        .target(
            name: "SwiftTunnelTransparentProxyProvider",
            dependencies: ["SwiftTunnelMacOSShared"],
            linkerSettings: [
                .linkedFramework("Network"),
                .linkedFramework("NetworkExtension"),
            ]
        ),
        .executableTarget(
            name: "swifttunnel-macos-helper",
            dependencies: ["SwiftTunnelMacOSShared"],
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
                .linkedFramework("SystemExtensions"),
            ]
        ),
    ]
)
