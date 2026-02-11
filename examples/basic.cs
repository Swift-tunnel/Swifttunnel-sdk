// SwiftTunnel SDK -- basic C# example
//
// Build:
//   dotnet new console -n SwiftTunnelDemo
//   Copy SwiftTunnelSDK.cs into the project
//   Copy swifttunnel.dll to the output directory
//   dotnet run
//
// Or as a single-file script with .NET 9+:
//   dotnet run basic.cs

using System;
using System.Text.Json;
using SwiftTunnel;

class Program
{
    static void Main(string[] args)
    {
        string email    = args.Length > 0 ? args[0] : "user@example.com";
        string password = args.Length > 1 ? args[1] : "password";
        string region   = args.Length > 2 ? args[2] : "singapore";

        using var sdk = new SwiftTunnelClient();

        Console.WriteLine($"SDK version: {sdk.Version()}");

        // Register callbacks
        sdk.OnStateChange(code =>
            Console.WriteLine($"[callback] state changed: {code}"));

        sdk.OnError((code, msg) =>
            Console.Error.WriteLine($"[callback] error {code}: {msg}"));

        sdk.OnProcessDetected((name, added) =>
            Console.WriteLine($"[callback] process {(added ? "added" : "removed")}: {name}"));
        sdk.OnAutoRoutingEvent(json =>
            Console.WriteLine($"[callback] auto-routing: {json}"));

        // Authenticate
        try
        {
            sdk.AuthSignIn(email, password);
        }
        catch (SwiftTunnelException ex)
        {
            Console.Error.WriteLine($"Auth failed ({ex.ErrorCode}): {ex.Message}");
            return;
        }

        Console.WriteLine($"Logged in: {sdk.IsLoggedIn}");
        Console.WriteLine($"User: {sdk.AuthGetUserJson()}");

        // Fetch servers and ping
        try
        {
            sdk.ServersFetch();
            Console.WriteLine($"Servers: {sdk.ServersGetJson()}");
            int latency = sdk.ServersPing(region);
            Console.WriteLine($"Ping {region}: {latency} ms");
        }
        catch (SwiftTunnelException ex)
        {
            Console.Error.WriteLine($"Servers error ({ex.ErrorCode}): {ex.Message}");
        }

        // Connect with split tunnelling + auto-routing
        try
        {
            var options = new
            {
                region,
                apps = new[] { "RobloxPlayerBeta.exe" },
                auto_routing = new
                {
                    enabled = true,
                    whitelisted_regions = new[] { "US East", "Tokyo" }
                }
            };
            sdk.ConnectEx(JsonSerializer.Serialize(options));

            Console.WriteLine($"State: {sdk.State}");
            Console.WriteLine($"State detail: {sdk.StateJson}");
            Console.WriteLine($"Tunneled processes: {sdk.TunneledProcessesJson}");
            Console.WriteLine($"Stats: {sdk.StatsJson}");
            Console.WriteLine($"Auto routing: {sdk.AutoRoutingJson}");
        }
        catch (SwiftTunnelException ex)
        {
            Console.Error.WriteLine($"Connect failed ({ex.ErrorCode}): {ex.Message}");
            return;
        }

        // Disconnect
        try
        {
            sdk.Disconnect();
        }
        catch (SwiftTunnelException ex)
        {
            Console.Error.WriteLine($"Disconnect failed ({ex.ErrorCode}): {ex.Message}");
        }

        // Sign out
        sdk.AuthSignOut();
        Console.WriteLine("Done");
    }
}
