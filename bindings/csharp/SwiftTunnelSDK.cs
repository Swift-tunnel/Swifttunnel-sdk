// SwiftTunnel SDK — C# P/Invoke bindings
//
// Usage:
//   using SwiftTunnel;
//   using var sdk = new SwiftTunnelClient();
//   sdk.AuthSignIn("user@example.com", "password");
//   sdk.ConnectEx("{\"region\":\"singapore\",\"apps\":[\"RobloxPlayerBeta.exe\"],\"forced_servers\":{\"us-east\":\"us-east-nj\"}}");

using System;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace SwiftTunnel
{
    // ── Callback delegates ─────────────────────────────────────────────────

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void StateChangeCallback(int stateCode, IntPtr ctx);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void ErrorCallback(int errorCode, IntPtr message, IntPtr ctx);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void ProcessDetectedCallback(IntPtr processName, int added, IntPtr ctx);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void AutoRoutingEventCallback(IntPtr eventJson, IntPtr ctx);

    // ── Raw P/Invoke declarations ──────────────────────────────────────────

    public static class SwiftTunnelNative
    {
        private const string Lib = "swifttunnel";

        // Core (4)
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int swifttunnel_init();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern void swifttunnel_cleanup();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr swifttunnel_version();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern void swifttunnel_free_string(IntPtr ptr);

        // Auth (8)
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int swifttunnel_auth_sign_in(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string email,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string password);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr swifttunnel_auth_start_oauth();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int swifttunnel_auth_poll_oauth();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern void swifttunnel_auth_cancel_oauth();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int swifttunnel_auth_refresh();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern void swifttunnel_auth_sign_out();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int swifttunnel_auth_is_logged_in();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr swifttunnel_auth_get_user_json();

        // Servers (3)
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int swifttunnel_servers_fetch();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr swifttunnel_servers_get_json();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int swifttunnel_servers_ping(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string region);

        // Connection (4)
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int swifttunnel_connect(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string region,
            [MarshalAs(UnmanagedType.LPUTF8Str)] string appsJson);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int swifttunnel_connect_ex(
            [MarshalAs(UnmanagedType.LPUTF8Str)] string optionsJson);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int swifttunnel_disconnect();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int swifttunnel_get_state();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr swifttunnel_get_state_json();

        // Split Tunnel (3)
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr swifttunnel_get_tunneled_processes();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr swifttunnel_get_stats_json();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr swifttunnel_get_auto_routing_json();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int swifttunnel_refresh_processes();

        // Callbacks (3)
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern void swifttunnel_on_state_change(
            StateChangeCallback? cb, IntPtr ctx);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern void swifttunnel_on_error(
            ErrorCallback? cb, IntPtr ctx);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern void swifttunnel_on_process_detected(
            ProcessDetectedCallback? cb, IntPtr ctx);

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern void swifttunnel_on_auto_routing_event(
            AutoRoutingEventCallback? cb, IntPtr ctx);

        // Error (3)
        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr swifttunnel_get_last_error();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern int swifttunnel_get_last_error_code();

        [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
        public static extern void swifttunnel_clear_error();
    }

    // ── High-level wrapper ─────────────────────────────────────────────────

    public class SwiftTunnelClient : IDisposable
    {
        private bool _disposed;

        // Hold delegate references to prevent GC collection while registered.
        private StateChangeCallback? _stateCallback;
        private ErrorCallback? _errorCallback;
        private ProcessDetectedCallback? _processCallback;
        private AutoRoutingEventCallback? _autoRoutingCallback;

        public SwiftTunnelClient()
        {
            int rc = SwiftTunnelNative.swifttunnel_init();
            if (rc != 0)
                throw new SwiftTunnelException(rc, GetLastError() ?? "init failed");
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
                // Unregister callbacks before cleanup
                SwiftTunnelNative.swifttunnel_on_state_change(null, IntPtr.Zero);
                SwiftTunnelNative.swifttunnel_on_error(null, IntPtr.Zero);
                SwiftTunnelNative.swifttunnel_on_process_detected(null, IntPtr.Zero);
                SwiftTunnelNative.swifttunnel_on_auto_routing_event(null, IntPtr.Zero);
                _stateCallback = null;
                _errorCallback = null;
                _processCallback = null;
                _autoRoutingCallback = null;

                SwiftTunnelNative.swifttunnel_cleanup();
            }
        }

        // ── Helpers ────────────────────────────────────────────────────────

        /// Read an SDK-allocated string and free it.
        private static string? ConsumeString(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero) return null;
            string s = Marshal.PtrToStringUTF8(ptr)!;
            SwiftTunnelNative.swifttunnel_free_string(ptr);
            return s;
        }

        private static void Check(int rc)
        {
            if (rc != 0)
            {
                string? msg = ConsumeString(SwiftTunnelNative.swifttunnel_get_last_error());
                throw new SwiftTunnelException(rc, msg ?? $"error code {rc}");
            }
        }

        public static string? GetLastError()
        {
            return ConsumeString(SwiftTunnelNative.swifttunnel_get_last_error());
        }

        public static int GetLastErrorCode()
        {
            return SwiftTunnelNative.swifttunnel_get_last_error_code();
        }

        public static void ClearError()
        {
            SwiftTunnelNative.swifttunnel_clear_error();
        }

        // ── Core ───────────────────────────────────────────────────────────

        public string Version()
        {
            return ConsumeString(SwiftTunnelNative.swifttunnel_version())
                   ?? throw new SwiftTunnelException(-1, "failed to get version");
        }

        // ── Auth ───────────────────────────────────────────────────────────

        public void AuthSignIn(string email, string password)
        {
            Check(SwiftTunnelNative.swifttunnel_auth_sign_in(email, password));
        }

        public string AuthStartOAuth()
        {
            IntPtr ptr = SwiftTunnelNative.swifttunnel_auth_start_oauth();
            return ConsumeString(ptr)
                   ?? throw new SwiftTunnelException(GetLastErrorCode(),
                        GetLastError() ?? "failed to start OAuth");
        }

        /// Returns 1 if complete, 0 if still waiting.
        public int AuthPollOAuth()
        {
            int rc = SwiftTunnelNative.swifttunnel_auth_poll_oauth();
            if (rc == -1)
                throw new SwiftTunnelException(GetLastErrorCode(),
                    GetLastError() ?? "OAuth poll error");
            return rc;
        }

        public void AuthCancelOAuth()
        {
            SwiftTunnelNative.swifttunnel_auth_cancel_oauth();
        }

        public void AuthRefresh()
        {
            Check(SwiftTunnelNative.swifttunnel_auth_refresh());
        }

        public void AuthSignOut()
        {
            SwiftTunnelNative.swifttunnel_auth_sign_out();
        }

        public bool IsLoggedIn
        {
            get => SwiftTunnelNative.swifttunnel_auth_is_logged_in() == 1;
        }

        public string? AuthGetUserJson()
        {
            // Includes additive `is_tester` in v1.1.x.
            return ConsumeString(SwiftTunnelNative.swifttunnel_auth_get_user_json());
        }

        // ── Servers ────────────────────────────────────────────────────────

        public void ServersFetch()
        {
            Check(SwiftTunnelNative.swifttunnel_servers_fetch());
        }

        public string? ServersGetJson()
        {
            return ConsumeString(SwiftTunnelNative.swifttunnel_servers_get_json());
        }

        /// Returns latency in ms, or -1 on error.
        public int ServersPing(string region)
        {
            return SwiftTunnelNative.swifttunnel_servers_ping(region);
        }

        // ── Connection ─────────────────────────────────────────────────────

        public void Connect(string region, string[]? apps = null)
        {
            string appsJson = apps != null
                ? JsonSerializer.Serialize(apps)
                : "[]";
            Check(SwiftTunnelNative.swifttunnel_connect(region, appsJson));
        }

        public void ConnectEx(string optionsJson)
        {
            // Additive v1.1.x options: custom_relay_server + forced_servers.
            Check(SwiftTunnelNative.swifttunnel_connect_ex(optionsJson));
        }

        public void Disconnect()
        {
            Check(SwiftTunnelNative.swifttunnel_disconnect());
        }

        /// Connection state code: 0=Disconnected, 1=FetchingConfig, 2=Connecting,
        /// 3=ConfiguringSplitTunnel, 4=Connected, 5=Disconnecting, -1=Error.
        public int State
        {
            get => SwiftTunnelNative.swifttunnel_get_state();
        }

        public string? StateJson
        {
            // Includes additive fields like assigned_ip + relay_auth_mode in v1.1.x.
            get => ConsumeString(SwiftTunnelNative.swifttunnel_get_state_json());
        }

        // ── Split Tunnel ───────────────────────────────────────────────────

        public string? TunneledProcessesJson
        {
            get => ConsumeString(SwiftTunnelNative.swifttunnel_get_tunneled_processes());
        }

        public string? StatsJson
        {
            get => ConsumeString(SwiftTunnelNative.swifttunnel_get_stats_json());
        }

        public string? AutoRoutingJson
        {
            get => ConsumeString(SwiftTunnelNative.swifttunnel_get_auto_routing_json());
        }

        public void RefreshProcesses()
        {
            Check(SwiftTunnelNative.swifttunnel_refresh_processes());
        }

        // ── Callbacks ──────────────────────────────────────────────────────

        public void OnStateChange(Action<int>? handler)
        {
            if (handler == null)
            {
                _stateCallback = null;
                SwiftTunnelNative.swifttunnel_on_state_change(null, IntPtr.Zero);
                return;
            }

            _stateCallback = (code, _) => handler(code);
            SwiftTunnelNative.swifttunnel_on_state_change(_stateCallback, IntPtr.Zero);
        }

        public void OnError(Action<int, string>? handler)
        {
            if (handler == null)
            {
                _errorCallback = null;
                SwiftTunnelNative.swifttunnel_on_error(null, IntPtr.Zero);
                return;
            }

            _errorCallback = (code, msgPtr, _) =>
            {
                string msg = msgPtr != IntPtr.Zero
                    ? Marshal.PtrToStringUTF8(msgPtr) ?? ""
                    : "";
                handler(code, msg);
            };
            SwiftTunnelNative.swifttunnel_on_error(_errorCallback, IntPtr.Zero);
        }

        public void OnProcessDetected(Action<string, bool>? handler)
        {
            if (handler == null)
            {
                _processCallback = null;
                SwiftTunnelNative.swifttunnel_on_process_detected(null, IntPtr.Zero);
                return;
            }

            _processCallback = (namePtr, added, _) =>
            {
                string name = namePtr != IntPtr.Zero
                    ? Marshal.PtrToStringUTF8(namePtr) ?? ""
                    : "";
                handler(name, added != 0);
            };
            SwiftTunnelNative.swifttunnel_on_process_detected(_processCallback, IntPtr.Zero);
        }

        public void OnAutoRoutingEvent(Action<string>? handler)
        {
            if (handler == null)
            {
                _autoRoutingCallback = null;
                SwiftTunnelNative.swifttunnel_on_auto_routing_event(null, IntPtr.Zero);
                return;
            }

            _autoRoutingCallback = (jsonPtr, _) =>
            {
                string payload = jsonPtr != IntPtr.Zero
                    ? Marshal.PtrToStringUTF8(jsonPtr) ?? ""
                    : "";
                handler(payload);
            };
            SwiftTunnelNative.swifttunnel_on_auto_routing_event(_autoRoutingCallback, IntPtr.Zero);
        }
    }

    // ── Exception type ─────────────────────────────────────────────────────

    public class SwiftTunnelException : Exception
    {
        public int ErrorCode { get; }

        public SwiftTunnelException(int code, string message)
            : base(message)
        {
            ErrorCode = code;
        }
    }
}
