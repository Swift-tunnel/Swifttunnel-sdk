# SwiftTunnel macOS SDK

Native macOS SwiftTunnel SDK with the same C ABI as the Windows SDK, implemented as a Rust `cdylib` plus Apple-side transparent proxy support.

Minimum Apple-side deployment target: macOS 15. The Swift package uses the modern `Network.NWEndpoint`-based transparent-proxy APIs that Apple exposes in the current Swift overlay.

## What Is Implemented

- Rust SDK core
  - Auth, token storage, server discovery, relay selection, relay auth, ping telemetry, callbacks, and the public FFI surface
- macOS split tunnel backend
  - `src/split_tunnel.rs` runs a localhost UDP bridge that accepts per-flow datagrams from a `NETransparentProxyProvider`
  - Outbound UDP payloads are re-wrapped into IPv4+UDP packets before being sent to the existing relay protocol
  - Relay responses are mapped back onto the original intercepted flow and written to the provider
- Apple support package
  - `apple/` contains a Swift package with the helper CLI, shared bridge codec, and reusable provider base class
- System Extension templates
  - `system-extension/` contains the thin provider entrypoint plus plist and entitlement templates for an Xcode host app

## Platform Mapping

| Windows Component | macOS Equivalent | Status |
|---|---|---|
| `ndisapi` split tunnel | `NETransparentProxyProvider` system extension | Implemented |
| Socket tuning (`SO_RCVBUF`, `IP_TOS`) | POSIX `setsockopt` | Reused in relay client |
| MTU detection (`GetBestInterfaceEx`) | existing non-Windows fallback in relay client | Reused |
| ETW process detection | provider flow metadata / signing identifier | Replaced |
| `GetTickCount64` monotonic time | `Instant` fallback | Reused |
| DPAPI credential storage | `keyring` on macOS Keychain | Reused |

## Architecture

macOS does split tunneling at the flow layer, not the packet layer.

1. The host app embeds a signed `NETransparentProxyProvider` system extension.
2. The Rust SDK starts the relay client and a localhost UDP bridge socket.
3. The Rust SDK invokes `swifttunnel-macos-helper`, which saves and starts an `NETransparentProxyManager`.
4. The provider accepts UDP flows, filters them by source app signing identifier, and forwards outbound payloads to Rust over the bridge protocol.
5. Rust reconstructs IPv4+UDP packets so the existing relay protocol stays `[session_id][IP packet]`.
6. Relay responses are de-multiplexed back to the original flow and written into the provider with `writeDatagrams`.

Current limitation: the bridge keeps the existing relay framing, so the macOS split tunnel path currently supports IPv4 UDP interception only. IPv6 capture is disabled in the generated helper configuration.

## App Matching

The public SDK API still uses the existing `apps` field. On macOS those entries should be app signing or bundle identifiers, for example:

```json
{
  "region": "singapore",
  "apps": ["com.roblox.RobloxPlayer"]
}
```

For compatibility, the macOS SDK normalizes common Roblox Windows aliases such as `RobloxPlayerBeta.exe` to `com.roblox.RobloxPlayer` before starting the provider.

## Directory Layout

```text
src/
  lib.rs                # C ABI entrypoint and shared SDK state
  split_tunnel.rs       # macOS flow bridge + helper orchestration
  auth/                 # shared auth client, OAuth listener, secure storage
  vpn/                  # shared relay client, config, auto-routing, servers
apple/
  Package.swift
  Sources/
    SwiftTunnelMacOSShared/
    SwiftTunnelTransparentProxyProvider/
    swifttunnel-macos-helper/
system-extension/
  TransparentProxyProvider.swift
  TransparentProxyExtension-Info.plist.template
  TransparentProxyExtension.entitlements.template
  HostApp.entitlements.template
```

## Build

```bash
# Rust SDK + generated C header
cd macos-sdk
cargo build --release

# Swift helper/provider package
cd apple
swift build
```

## Host App Integration

Apple requires the transparent proxy to be shipped inside a signed macOS app.

1. Add `apple/` as a Swift Package dependency in the host Xcode project.
2. Create a System Extension target and use `system-extension/TransparentProxyProvider.swift` as the entrypoint.
3. Link that target against the `SwiftTunnelTransparentProxyProvider` product.
4. Fill in the bundle identifiers and entitlements from `system-extension/*.template`.
5. Embed the system extension in the host app and sign both with the required Network Extension entitlements.
6. Build `swifttunnel-macos-helper` and bundle it with the host app so the Rust SDK can invoke it.

The helper expects the provider bundle identifier `net.swifttunnel.macos.transparent-proxy.extension` unless the SDK is rebuilt with a different constant.
