#!/usr/bin/env python3
"""SwiftTunnel SDK -- basic Python example.

Usage:
    python basic.py [email] [password] [region]

Set SWIFTTUNNEL_LIB to the path of the shared library if it is not in the
current directory.
"""

import sys
import os

# Add the bindings directory to the import path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bindings", "python"))

from swifttunnel import SwiftTunnel, SwiftTunnelError


def main() -> None:
    email    = sys.argv[1] if len(sys.argv) > 1 else "user@example.com"
    password = sys.argv[2] if len(sys.argv) > 2 else "password"
    region   = sys.argv[3] if len(sys.argv) > 3 else "singapore"

    with SwiftTunnel() as sdk:
        print(f"SDK version: {sdk.version}")

        # Register callbacks
        sdk.on_state_change(
            lambda code: print(f"[callback] state changed: {code}")
        )
        sdk.on_error(
            lambda code, msg: print(f"[callback] error {code}: {msg}", file=sys.stderr)
        )
        sdk.on_process_detected(
            lambda name, added: print(
                f"[callback] process {'added' if added else 'removed'}: {name}"
            )
        )

        # Authenticate
        try:
            sdk.auth_sign_in(email, password)
        except SwiftTunnelError as e:
            print(f"Auth failed ({e.code}): {e}", file=sys.stderr)
            return

        print(f"Logged in: {sdk.is_logged_in}")
        print(f"User: {sdk.auth_get_user()}")

        # Fetch servers and ping
        try:
            sdk.servers_fetch()
            print(f"Servers: {sdk.servers_get()}")
            latency = sdk.servers_ping(region)
            print(f"Ping {region}: {latency} ms")
        except SwiftTunnelError as e:
            print(f"Servers error ({e.code}): {e}", file=sys.stderr)

        # Connect with split tunnelling
        try:
            sdk.connect(region, ["RobloxPlayerBeta.exe"])

            print(f"State: {sdk.state}")
            print(f"State detail: {sdk.state_json}")
            print(f"Tunneled processes: {sdk.tunneled_processes}")
            print(f"Stats: {sdk.stats}")
        except SwiftTunnelError as e:
            print(f"Connect failed ({e.code}): {e}", file=sys.stderr)
            return

        # Disconnect
        try:
            sdk.disconnect()
        except SwiftTunnelError as e:
            print(f"Disconnect failed ({e.code}): {e}", file=sys.stderr)

        # Sign out
        sdk.auth_sign_out()
        print("Done")


if __name__ == "__main__":
    main()
