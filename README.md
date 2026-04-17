# SwiftTunnel SDK

Platform SDK container for third-party SwiftTunnel integrations.

## Layout

| Directory | Status | Purpose |
|-----------|--------|---------|
| `windows-sdk/` | Production | Existing Windows C ABI SDK with ndisapi-based split tunneling |
| `macos-sdk/` | Implemented | macOS C ABI SDK built around `NETransparentProxyProvider`, a Swift helper, and a host-app system extension |

## Build

```bash
# Windows SDK
cd windows-sdk && cargo build --release

# macOS Rust SDK
cd macos-sdk && cargo build --release

# macOS helper/provider Swift package
cd macos-sdk/apple && swift build
```

## Windows SDK

The current shipping SDK lives in [`windows-sdk/`](windows-sdk/README.md). It keeps the existing 32-function C ABI, V3 relay client, built-in auth flow, Windows keyring storage, ETW process detection, and ndisapi packet interception.

## Release 1.3.0 (Windows + macOS)

- `swifttunnel_get_stats_json()` includes a new `relay_health` string field: one of `"healthy"`, `"no_traffic_yet"`, `"stale"`, `"dead"`.
- UDP sender thread is wrapped in `catch_unwind`; sender-thread panics are surfaced instead of silently halting the tunnel.
- New async `UdpRelay::send_keepalive_burst_async()` yields via tokio instead of `std::thread::sleep`.
- FFI surface unchanged (still 32 functions); existing `get_stats_json` callers gain one optional new field.

## macOS SDK

[`macos-sdk/`](macos-sdk/README.md) now contains the full macOS source implementation. It keeps the same FFI/API surface as the Windows SDK, but the split-tunnel layer is implemented with a Swift `NETransparentProxyProvider`, a helper CLI that manages `NETransparentProxyManager`, and a localhost UDP bridge into the Rust relay client. The Apple-side package currently targets macOS 15.

| Windows Component | macOS Equivalent | Effort |
|---|---|---|
| `ndisapi` split tunnel | `NETransparentProxyProvider` System Extension | Major |
| Socket tuning | POSIX `setsockopt` | Trivial |
| MTU detection | `getifaddrs()` + `route get` | Small |
| ETW process detection | `sourceAppAuditToken` on intercepted flows | None |
| `GetTickCount64` monotonic time | Existing `Instant` fallback | None |
| DPAPI credential storage | `keyring` on macOS Keychain | Trivial |

## Relay Framing

The macOS SDK currently preserves the existing relay wire format by reconstructing an IPv4+UDP packet from provider flow metadata before forwarding to the relay. That keeps the relay server unchanged at the cost of limiting the transparent-proxy path to IPv4 UDP flows for now.

Apple-specific note: the source tree is complete, but shipping the macOS SDK still requires a signed host app, Network Extension entitlements, and system-extension approval on the user’s Mac.
