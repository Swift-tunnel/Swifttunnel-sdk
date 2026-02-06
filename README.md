# SwiftTunnel SDK

Native library for integrating SwiftTunnel VPN into third-party applications. Provides a C ABI (`cdylib`) with 28 functions covering authentication, server selection, V3 relay connection, and per-process split tunneling.

## Features

- **V3 Relay** - Unencrypted UDP relay for minimum latency gaming (`[session_id][payload]` to port 51821)
- **Forced Split Tunneling** - Per-process routing via ndisapi + per-CPU packet workers
- **Built-in Auth** - Email/password and Google OAuth with auto token refresh
- **Credential Storage** - Windows Credential Manager (DPAPI)
- **ETW Process Detection** - Instant game process detection within microseconds of launch
- **Language Bindings** - C header (auto-generated), C# P/Invoke, Python ctypes

## Quick Start

### Build

```bash
cargo build --release
# Output: target/release/swifttunnel.dll
# Header: include/swifttunnel.h
```

### C

```c
#include "swifttunnel.h"

int main() {
    swifttunnel_init();
    swifttunnel_auth_sign_in("user@example.com", "password");

    const char* apps = "[\"RobloxPlayerBeta.exe\"]";
    swifttunnel_connect("singapore", apps);

    // Game traffic is now relayed through the VPN
    // Other traffic bypasses normally

    swifttunnel_disconnect();
    swifttunnel_cleanup();
}
```

### C#

```csharp
using SwiftTunnelSDK;

SwiftTunnel.Init();
SwiftTunnel.AuthSignIn("user@example.com", "password");
SwiftTunnel.Connect("singapore", new[] { "RobloxPlayerBeta.exe" });

// ... game plays with VPN routing ...

SwiftTunnel.Disconnect();
SwiftTunnel.Cleanup();
```

### Python

```python
from swifttunnel import SwiftTunnel

with SwiftTunnel() as vpn:
    vpn.auth_sign_in("user@example.com", "password")
    vpn.connect("singapore", ["RobloxPlayerBeta.exe"])

    # ... game plays with VPN routing ...

    vpn.disconnect()
```

## API Reference

### Core

| Function | Description |
|----------|-------------|
| `swifttunnel_init()` | Initialize the SDK |
| `swifttunnel_cleanup()` | Tear down and release resources |
| `swifttunnel_version()` | Get SDK version string |
| `swifttunnel_free_string(ptr)` | Free a string returned by the SDK |

### Authentication

| Function | Description |
|----------|-------------|
| `swifttunnel_auth_sign_in(email, password)` | Sign in with email/password |
| `swifttunnel_auth_start_oauth()` | Start Google OAuth, returns URL |
| `swifttunnel_auth_poll_oauth()` | Poll OAuth completion (1=done, 0=waiting, -1=error) |
| `swifttunnel_auth_cancel_oauth()` | Cancel OAuth flow |
| `swifttunnel_auth_refresh()` | Refresh access token |
| `swifttunnel_auth_sign_out()` | Sign out and clear credentials |
| `swifttunnel_auth_is_logged_in()` | Check login status (1/0) |
| `swifttunnel_auth_get_user_json()` | Get user info as JSON |

### Servers

| Function | Description |
|----------|-------------|
| `swifttunnel_servers_fetch()` | Fetch server list from API |
| `swifttunnel_servers_get_json()` | Get cached server list as JSON |
| `swifttunnel_servers_ping(region)` | Measure latency to region (ms) |

### Connection

| Function | Description |
|----------|-------------|
| `swifttunnel_connect(region, apps_json)` | Connect V3 relay with split tunnel |
| `swifttunnel_disconnect()` | Disconnect |
| `swifttunnel_get_state()` | Get state code (0=disconnected, 4=connected, -1=error) |
| `swifttunnel_get_state_json()` | Get detailed state as JSON |

### Split Tunnel

| Function | Description |
|----------|-------------|
| `swifttunnel_get_tunneled_processes()` | Get tunneled process names (JSON array) |
| `swifttunnel_get_stats_json()` | Get packet stats (sent/received) |
| `swifttunnel_refresh_processes()` | Trigger process cache refresh |

### Callbacks

| Function | Description |
|----------|-------------|
| `swifttunnel_on_state_change(cb, ctx)` | Register state change callback |
| `swifttunnel_on_error(cb, ctx)` | Register error callback |
| `swifttunnel_on_process_detected(cb, ctx)` | Register process detection callback |

### Error

| Function | Description |
|----------|-------------|
| `swifttunnel_get_last_error()` | Get last error message |
| `swifttunnel_get_last_error_code()` | Get last error code |
| `swifttunnel_clear_error()` | Clear error state |

## Connection States

| Code | State |
|------|-------|
| 0 | Disconnected |
| 1 | FetchingConfig |
| 2 | Connecting |
| 3 | ConfiguringSplitTunnel |
| 4 | Connected |
| 5 | Disconnecting |
| -1 | Error |

## Architecture

```
swifttunnel_connect("singapore", ["game.exe"])
  |
  +-- 1. Auth check -> refresh token if needed
  +-- 2. POST /api/vpn/generate-config -> VpnConfig
  +-- 3. UdpRelay::new(server:51821) -> session_id
  +-- 4. SplitTunnelDriver (ndisapi + per-CPU workers + ETW)
  +-- 5. Connected -> callback fired
```

### Packet Flow

```
game.exe UDP packet
  -> ndisapi intercepts on physical adapter
  -> ParallelInterceptor (hash dispatch to CPU worker)
  -> ProcessCache O(1) lookup -> PID -> process name
  -> In tunnel_apps? YES -> [session_id][payload] -> relay:51821
  -> In tunnel_apps? NO  -> passthrough
```

## Project Structure

```
src/
  lib.rs                    # 28 FFI functions
  runtime.rs                # Tokio runtime (lazy global)
  error.rs                  # Error types and codes
  callbacks.rs              # State/error/process callbacks
  auth/                     # Authentication (manager, client, storage, OAuth)
  vpn/                      # V3 relay, server list, config, connection state machine
  split_tunnel/             # ndisapi interceptor, process cache, tracker, ETW watcher
bindings/
  csharp/SwiftTunnelSDK.cs  # C# P/Invoke wrapper
  python/swifttunnel.py     # Python ctypes wrapper
examples/
  basic.c, basic.cs, basic.py
include/
  swifttunnel.h             # Auto-generated C header (cbindgen)
```

## Requirements

- **Windows 10/11** (64-bit)
- **Administrator privileges** (for ndisapi packet interception)
- **Windows Packet Filter driver** (ndisapi.sys)
- **Rust toolchain** (for building)

## License

Proprietary - SwiftTunnel
