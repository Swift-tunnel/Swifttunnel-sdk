# System Extension Notes

The macOS split tunnel lives in a `NETransparentProxyProvider` System Extension. This directory now holds the extension-side entrypoint plus build templates; the reusable implementation lives in the Swift package under `../apple`.

## Responsibilities

- Accept UDP flows from Network Extension.
- Match flows by source app signing identifier.
- Bridge tunneled UDP traffic to the Rust SDK over a localhost UDP socket.
- Accept provider messages from the helper CLI for live status and config updates.
- Keep loopback traffic out of the transparent proxy so the Rust bridge does not recurse.

## Files

- `main.swift`
  - System extension executable entrypoint that starts Network Extension system-extension mode
- `TransparentProxyProvider.swift`
  - Thin extension entrypoint that subclasses the reusable provider base from `SwiftTunnelTransparentProxyProvider`
- `TransparentProxyExtension-Info.plist.template`
  - Template Info.plist for the system extension target
- `TransparentProxyExtension.entitlements.template`
  - Template entitlements for the system extension target
- `HostApp.entitlements.template`
  - Template entitlements for the containing macOS app that installs and controls the extension

## Build Layout

The intended Xcode setup is:

1. Add the Swift package in `../apple` to the containing macOS app project.
2. Create a System Extension target that includes `main.swift` and `TransparentProxyProvider.swift`.
3. Link that target against the `SwiftTunnelTransparentProxyProvider` package product.
4. Use `TransparentProxyExtension-Info.plist.template` as the target Info.plist, keeping both the `NetworkExtension` provider-class mapping and the `NSExtension` point identifier.
5. Fill in the bundle identifiers and Team / entitlement values in the template plist and entitlement files.
6. Add `NSSystemExtensionUsageDescription` to the containing app's Info.plist so activation prompts have a user-facing explanation.
7. Keep the provider bundle identifier aligned with the Rust constant in `../src/split_tunnel.rs` (`net.swifttunnel.macos.transparent-proxy.extension` by default).
