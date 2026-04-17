# SwiftTunnel macOS Apple Support

Swift sources that the macOS SDK needs on the Apple side.

Deployment target: macOS 15.

- `swifttunnel-macos-helper`
  - Configures `NETransparentProxyManager`
  - Starts and stops the provider
  - Sends provider messages for live status and config updates
  - Can submit a system extension activation request
- `SwiftTunnelTransparentProxyProvider`
  - Reusable provider implementation for the system extension target
  - Bridges UDP flows to the Rust SDK over a localhost UDP socket
- `SwiftTunnelMacOSShared`
  - Shared bridge protocol and provider configuration types

The Rust SDK invokes `swifttunnel-macos-helper` when the macOS split tunnel starts. The containing app still has to ship the helper and the system extension inside a signed bundle with the required Network Extension entitlements.

## Build

```bash
cd apple
swift build
```

## Helper Commands

```bash
# Show saved manager state
swift run swifttunnel-macos-helper status \
  --provider-bundle-id net.swifttunnel.macos.transparent-proxy.extension

# Submit the one-time system extension activation request
swift run swifttunnel-macos-helper activate \
  --extension-bundle-id net.swifttunnel.macos.transparent-proxy.extension

# Save config and start the transparent proxy
swift run swifttunnel-macos-helper start \
  --provider-bundle-id net.swifttunnel.macos.transparent-proxy.extension \
  --config-json '{"bridge_host":"127.0.0.1","bridge_port":18421,"tunnel_app_identifiers":["com.roblox.RobloxPlayer"],"capture_ipv6":false,"localized_description":"SwiftTunnel"}'

# Send a live provider message
swift run swifttunnel-macos-helper send \
  --provider-bundle-id net.swifttunnel.macos.transparent-proxy.extension \
  --message-json '{"command":"status"}'
```

`config-json` uses macOS signing or bundle identifiers in `tunnel_app_identifiers`. The transparent proxy side currently bridges IPv4 UDP flows to Rust so the relay protocol can stay `[session_id][IP packet]`.
