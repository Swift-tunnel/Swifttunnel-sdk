"""SwiftTunnel SDK -- Python ctypes bindings.

Usage:
    from swifttunnel import SwiftTunnel

    with SwiftTunnel() as sdk:
        sdk.auth_sign_in("user@example.com", "password")
        sdk.connect("singapore", ["RobloxPlayerBeta.exe"])
        print(sdk.state_json)
        sdk.disconnect()
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import sys
from ctypes import (
    CDLL,
    CFUNCTYPE,
    POINTER,
    c_char_p,
    c_int,
    c_void_p,
)
from typing import Any, Callable

# ── Library loading ─────────────────────────────────────────────────────────

_LIB: CDLL | None = None


def _find_library() -> str:
    """Resolve the shared library path."""
    system = platform.system()
    if system == "Windows":
        name = "swifttunnel.dll"
    elif system == "Darwin":
        name = "libswifttunnel.dylib"
    else:
        name = "libswifttunnel.so"

    env = os.environ.get("SWIFTTUNNEL_LIB")
    if env:
        return env

    # Try alongside this file, then cwd
    here = os.path.dirname(os.path.abspath(__file__))
    for d in [here, os.getcwd()]:
        candidate = os.path.join(d, name)
        if os.path.isfile(candidate):
            return candidate

    return name  # fall back to system search


def _load_lib() -> CDLL:
    global _LIB
    if _LIB is not None:
        return _LIB

    lib = CDLL(_find_library())

    # ── Core (4) ────────────────────────────────────────────────────────
    lib.swifttunnel_init.argtypes = []
    lib.swifttunnel_init.restype = c_int

    lib.swifttunnel_cleanup.argtypes = []
    lib.swifttunnel_cleanup.restype = None

    lib.swifttunnel_version.argtypes = []
    lib.swifttunnel_version.restype = c_void_p

    lib.swifttunnel_free_string.argtypes = [c_void_p]
    lib.swifttunnel_free_string.restype = None

    # ── Auth (8) ────────────────────────────────────────────────────────
    lib.swifttunnel_auth_sign_in.argtypes = [c_char_p, c_char_p]
    lib.swifttunnel_auth_sign_in.restype = c_int

    lib.swifttunnel_auth_start_oauth.argtypes = []
    lib.swifttunnel_auth_start_oauth.restype = c_void_p

    lib.swifttunnel_auth_poll_oauth.argtypes = []
    lib.swifttunnel_auth_poll_oauth.restype = c_int

    lib.swifttunnel_auth_cancel_oauth.argtypes = []
    lib.swifttunnel_auth_cancel_oauth.restype = None

    lib.swifttunnel_auth_refresh.argtypes = []
    lib.swifttunnel_auth_refresh.restype = c_int

    lib.swifttunnel_auth_sign_out.argtypes = []
    lib.swifttunnel_auth_sign_out.restype = None

    lib.swifttunnel_auth_is_logged_in.argtypes = []
    lib.swifttunnel_auth_is_logged_in.restype = c_int

    lib.swifttunnel_auth_get_user_json.argtypes = []
    lib.swifttunnel_auth_get_user_json.restype = c_void_p

    # ── Servers (3) ─────────────────────────────────────────────────────
    lib.swifttunnel_servers_fetch.argtypes = []
    lib.swifttunnel_servers_fetch.restype = c_int

    lib.swifttunnel_servers_get_json.argtypes = []
    lib.swifttunnel_servers_get_json.restype = c_void_p

    lib.swifttunnel_servers_ping.argtypes = [c_char_p]
    lib.swifttunnel_servers_ping.restype = c_int

    # ── Connection (4) ──────────────────────────────────────────────────
    lib.swifttunnel_connect.argtypes = [c_char_p, c_char_p]
    lib.swifttunnel_connect.restype = c_int

    lib.swifttunnel_connect_ex.argtypes = [c_char_p]
    lib.swifttunnel_connect_ex.restype = c_int

    lib.swifttunnel_disconnect.argtypes = []
    lib.swifttunnel_disconnect.restype = c_int

    lib.swifttunnel_get_state.argtypes = []
    lib.swifttunnel_get_state.restype = c_int

    lib.swifttunnel_get_state_json.argtypes = []
    lib.swifttunnel_get_state_json.restype = c_void_p

    # ── Split Tunnel (3) ────────────────────────────────────────────────
    lib.swifttunnel_get_tunneled_processes.argtypes = []
    lib.swifttunnel_get_tunneled_processes.restype = c_void_p

    lib.swifttunnel_get_stats_json.argtypes = []
    lib.swifttunnel_get_stats_json.restype = c_void_p

    lib.swifttunnel_get_auto_routing_json.argtypes = []
    lib.swifttunnel_get_auto_routing_json.restype = c_void_p

    lib.swifttunnel_refresh_processes.argtypes = []
    lib.swifttunnel_refresh_processes.restype = c_int

    # ── Callbacks (3) ───────────────────────────────────────────────────
    STATE_CB = CFUNCTYPE(None, c_int, c_void_p)
    ERROR_CB = CFUNCTYPE(None, c_int, c_char_p, c_void_p)
    PROCESS_CB = CFUNCTYPE(None, c_char_p, c_int, c_void_p)
    AUTO_ROUTING_CB = CFUNCTYPE(None, c_char_p, c_void_p)

    lib.swifttunnel_on_state_change.argtypes = [STATE_CB, c_void_p]
    lib.swifttunnel_on_state_change.restype = None

    lib.swifttunnel_on_error.argtypes = [ERROR_CB, c_void_p]
    lib.swifttunnel_on_error.restype = None

    lib.swifttunnel_on_process_detected.argtypes = [PROCESS_CB, c_void_p]
    lib.swifttunnel_on_process_detected.restype = None

    lib.swifttunnel_on_auto_routing_event.argtypes = [AUTO_ROUTING_CB, c_void_p]
    lib.swifttunnel_on_auto_routing_event.restype = None

    # ── Error (3) ───────────────────────────────────────────────────────
    lib.swifttunnel_get_last_error.argtypes = []
    lib.swifttunnel_get_last_error.restype = c_void_p

    lib.swifttunnel_get_last_error_code.argtypes = []
    lib.swifttunnel_get_last_error_code.restype = c_int

    lib.swifttunnel_clear_error.argtypes = []
    lib.swifttunnel_clear_error.restype = None

    _LIB = lib
    return lib


# ── Callback CFUNCTYPE aliases ──────────────────────────────────────────────

STATE_CB_TYPE = CFUNCTYPE(None, c_int, c_void_p)
ERROR_CB_TYPE = CFUNCTYPE(None, c_int, c_char_p, c_void_p)
PROCESS_CB_TYPE = CFUNCTYPE(None, c_char_p, c_int, c_void_p)
AUTO_ROUTING_CB_TYPE = CFUNCTYPE(None, c_char_p, c_void_p)


# ── Exception ───────────────────────────────────────────────────────────────

class SwiftTunnelError(Exception):
    """Raised when an SDK call fails."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


# ── Helper ──────────────────────────────────────────────────────────────────

def _consume_string(lib: CDLL, ptr: int | None) -> str | None:
    """Read a C string allocated by the SDK and free it."""
    if not ptr:
        return None
    s = ctypes.cast(ptr, c_char_p).value
    lib.swifttunnel_free_string(ptr)
    return s.decode("utf-8") if s else None


def _check(lib: CDLL, rc: int) -> None:
    if rc != 0:
        msg = _consume_string(lib, lib.swifttunnel_get_last_error())
        raise SwiftTunnelError(rc, msg or f"error code {rc}")


# ── High-level wrapper ─────────────────────────────────────────────────────

class SwiftTunnel:
    """Pythonic wrapper around the SwiftTunnel C SDK.

    Supports context-manager usage::

        with SwiftTunnel() as sdk:
            sdk.auth_sign_in("user@example.com", "password")
    """

    def __init__(self, *, auto_init: bool = True):
        self._lib = _load_lib()
        # Hold references to prevent GC of C callbacks
        self._state_cb = None
        self._error_cb = None
        self._process_cb = None
        self._auto_routing_cb = None
        if auto_init:
            self.init()

    def __enter__(self) -> "SwiftTunnel":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.cleanup()

    # ── Core ────────────────────────────────────────────────────────────

    def init(self) -> None:
        _check(self._lib, self._lib.swifttunnel_init())

    def cleanup(self) -> None:
        self.on_state_change(None)
        self.on_error(None)
        self.on_process_detected(None)
        self.on_auto_routing_event(None)
        self._lib.swifttunnel_cleanup()

    @property
    def version(self) -> str:
        ptr = self._lib.swifttunnel_version()
        s = _consume_string(self._lib, ptr)
        if s is None:
            raise SwiftTunnelError(-1, "failed to get version")
        return s

    # ── Auth ────────────────────────────────────────────────────────────

    def auth_sign_in(self, email: str, password: str) -> None:
        _check(
            self._lib,
            self._lib.swifttunnel_auth_sign_in(
                email.encode("utf-8"), password.encode("utf-8")
            ),
        )

    def auth_start_oauth(self) -> str:
        ptr = self._lib.swifttunnel_auth_start_oauth()
        url = _consume_string(self._lib, ptr)
        if url is None:
            msg = _consume_string(self._lib, self._lib.swifttunnel_get_last_error())
            raise SwiftTunnelError(
                self._lib.swifttunnel_get_last_error_code(),
                msg or "failed to start OAuth",
            )
        return url

    def auth_poll_oauth(self) -> int:
        """Returns 1 if complete, 0 if still waiting. Raises on error."""
        rc = self._lib.swifttunnel_auth_poll_oauth()
        if rc == -1:
            msg = _consume_string(self._lib, self._lib.swifttunnel_get_last_error())
            raise SwiftTunnelError(
                self._lib.swifttunnel_get_last_error_code(),
                msg or "OAuth poll error",
            )
        return rc

    def auth_cancel_oauth(self) -> None:
        self._lib.swifttunnel_auth_cancel_oauth()

    def auth_refresh(self) -> None:
        _check(self._lib, self._lib.swifttunnel_auth_refresh())

    def auth_sign_out(self) -> None:
        self._lib.swifttunnel_auth_sign_out()

    @property
    def is_logged_in(self) -> bool:
        return self._lib.swifttunnel_auth_is_logged_in() == 1

    def auth_get_user(self) -> dict | None:
        ptr = self._lib.swifttunnel_auth_get_user_json()
        s = _consume_string(self._lib, ptr)
        return json.loads(s) if s else None

    # ── Servers ─────────────────────────────────────────────────────────

    def servers_fetch(self) -> None:
        _check(self._lib, self._lib.swifttunnel_servers_fetch())

    def servers_get(self) -> dict | None:
        ptr = self._lib.swifttunnel_servers_get_json()
        s = _consume_string(self._lib, ptr)
        return json.loads(s) if s else None

    def servers_ping(self, region: str) -> int:
        """Returns latency in ms, or -1 on error."""
        return self._lib.swifttunnel_servers_ping(region.encode("utf-8"))

    # ── Connection ──────────────────────────────────────────────────────

    def connect(self, region: str, apps: list[str] | None = None) -> None:
        apps_json = json.dumps(apps or [])
        _check(
            self._lib,
            self._lib.swifttunnel_connect(
                region.encode("utf-8"), apps_json.encode("utf-8")
            ),
        )

    def connect_ex(self, options: dict[str, Any] | str) -> None:
        if isinstance(options, str):
            payload = options
        else:
            payload = json.dumps(options)
        _check(
            self._lib,
            self._lib.swifttunnel_connect_ex(payload.encode("utf-8")),
        )

    def disconnect(self) -> None:
        _check(self._lib, self._lib.swifttunnel_disconnect())

    @property
    def state(self) -> int:
        """Connection state code: 0=Disconnected, 1=FetchingConfig, 2=Connecting,
        3=ConfiguringSplitTunnel, 4=Connected, 5=Disconnecting, -1=Error."""
        return self._lib.swifttunnel_get_state()

    @property
    def state_json(self) -> dict | None:
        ptr = self._lib.swifttunnel_get_state_json()
        s = _consume_string(self._lib, ptr)
        return json.loads(s) if s else None

    # ── Split Tunnel ────────────────────────────────────────────────────

    @property
    def tunneled_processes(self) -> list[str]:
        ptr = self._lib.swifttunnel_get_tunneled_processes()
        s = _consume_string(self._lib, ptr)
        return json.loads(s) if s else []

    @property
    def stats(self) -> dict | None:
        ptr = self._lib.swifttunnel_get_stats_json()
        s = _consume_string(self._lib, ptr)
        return json.loads(s) if s else None

    @property
    def auto_routing_json(self) -> dict | None:
        ptr = self._lib.swifttunnel_get_auto_routing_json()
        s = _consume_string(self._lib, ptr)
        return json.loads(s) if s else None

    def refresh_processes(self) -> None:
        _check(self._lib, self._lib.swifttunnel_refresh_processes())

    # ── Callbacks ───────────────────────────────────────────────────────

    def on_state_change(self, handler: Callable[[int], None] | None) -> None:
        if handler is None:
            self._state_cb = None
            self._lib.swifttunnel_on_state_change(
                ctypes.cast(None, STATE_CB_TYPE), None
            )
            return

        @STATE_CB_TYPE
        def _cb(code: int, _ctx: Any) -> None:
            handler(code)

        self._state_cb = _cb
        self._lib.swifttunnel_on_state_change(self._state_cb, None)

    def on_error(self, handler: Callable[[int, str], None] | None) -> None:
        if handler is None:
            self._error_cb = None
            self._lib.swifttunnel_on_error(
                ctypes.cast(None, ERROR_CB_TYPE), None
            )
            return

        @ERROR_CB_TYPE
        def _cb(code: int, msg_ptr: bytes | None, _ctx: Any) -> None:
            msg = msg_ptr.decode("utf-8") if msg_ptr else ""
            handler(code, msg)

        self._error_cb = _cb
        self._lib.swifttunnel_on_error(self._error_cb, None)

    def on_process_detected(
        self, handler: Callable[[str, bool], None] | None
    ) -> None:
        if handler is None:
            self._process_cb = None
            self._lib.swifttunnel_on_process_detected(
                ctypes.cast(None, PROCESS_CB_TYPE), None
            )
            return

        @PROCESS_CB_TYPE
        def _cb(name_ptr: bytes | None, added: int, _ctx: Any) -> None:
            name = name_ptr.decode("utf-8") if name_ptr else ""
            handler(name, added != 0)

        self._process_cb = _cb
        self._lib.swifttunnel_on_process_detected(self._process_cb, None)

    def on_auto_routing_event(
        self, handler: Callable[[str], None] | None
    ) -> None:
        if handler is None:
            self._auto_routing_cb = None
            self._lib.swifttunnel_on_auto_routing_event(
                ctypes.cast(None, AUTO_ROUTING_CB_TYPE), None
            )
            return

        @AUTO_ROUTING_CB_TYPE
        def _cb(event_ptr: bytes | None, _ctx: Any) -> None:
            payload = event_ptr.decode("utf-8") if event_ptr else ""
            handler(payload)

        self._auto_routing_cb = _cb
        self._lib.swifttunnel_on_auto_routing_event(self._auto_routing_cb, None)

    # ── Error ───────────────────────────────────────────────────────────

    def get_last_error(self) -> str | None:
        return _consume_string(self._lib, self._lib.swifttunnel_get_last_error())

    def get_last_error_code(self) -> int:
        return self._lib.swifttunnel_get_last_error_code()

    def clear_error(self) -> None:
        self._lib.swifttunnel_clear_error()
