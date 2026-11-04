using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol.Client;

namespace CodeSentinel.Mcp.Tests;

// Starts the real server executable and talks to it over stdin/stdout, the way Claude
// Code or Cursor do. With the stdio transport every byte on stdout must belong to a
// JSON-RPC message; a single log line there breaks the client.
public sealed class StdioServerTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private static string ServerAssembly { get; } = Path.Combine(AppContext.BaseDirectory, "codesentinel-mcp.dll");

    // dotnet test sets DOTNET_HOST_PATH to the muxer that is running the tests.
    private static string DotnetHost { get; } =
        Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } host ? host : "dotnet";

    [Fact]
    public async Task Stdout_CarriesOnlyJsonRpcMessages_AndLogsGoToStderr()
    {
        using var cts = new CancellationTokenSource(Timeout);
        using var server = StartServer("--allowed-root", RepositoryPaths.Root);
        var stderr = server.StandardError.ReadToEndAsync(cts.Token);

        await SendAsync(server, new
        {
            jsonrpc = "2.0",
            id = 1,
            method = "initialize",
            @params = new
            {
                protocolVersion = "2025-06-18",
                capabilities = new { },
                clientInfo = new { name = "tests", version = "1" },
            },
        });
        await SendAsync(server, new { jsonrpc = "2.0", method = "notifications/initialized" });
        await SendAsync(server, new
        {
            jsonrpc = "2.0",
            id = 2,
            method = "tools/call",
            @params = new
            {
                name = "scan_path",
                arguments = new { path = "samples/vulnerable-repo", maxFindings = 500 },
            },
        });

        var lines = new List<string>();
        JsonNode? scanResponse = null;
        while (scanResponse is null)
        {
            var line = await server.StandardOutput.ReadLineAsync(cts.Token)
                ?? throw new InvalidOperationException("The server closed stdout before answering.");
            lines.Add(line);

            var message = JsonNode.Parse(line)!;
            if (message["id"]?.GetValue<int>() == 2)
                scanResponse = message;
        }

        server.StandardInput.Close();
        lines.AddRange((await server.StandardOutput.ReadToEndAsync(cts.Token))
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        await server.WaitForExitAsync(cts.Token);

        foreach (var line in lines)
        {
            var parse = () => JsonDocument.Parse(line);
            parse.Should().NotThrow(because: "stdout must only carry JSON-RPC, but got: {0}", line);
            JsonNode.Parse(line)!["jsonrpc"]!.GetValue<string>().Should().Be("2.0");
        }

        scanResponse["result"]!["structuredContent"]!["score"]!.GetValue<int>().Should().Be(0);
        (await stderr).Should().Contain("Allowed roots:").And.Contain("Starting scan");
    }

    [Fact]
    public async Task ScanPathResponse_OnTheWire_ContainsNoSecretValue()
    {
        await using var client = await ConnectAsync(RepositoryPaths.Root);

        var response = await client.CallToolAsync(
            "scan_path",
            new Dictionary<string, object?> { ["path"] = "samples/vulnerable-repo", ["maxFindings"] = 500 });

        response.IsError.Should().NotBe(true);
        var wire = JsonSerializer.Serialize(response, ModelContextProtocol.McpJsonUtilities.DefaultOptions);
        wire.Should().Contain(FixtureSecrets.Marker);
        foreach (var secret in FixtureSecrets.Known)
            wire.Should().NotContain(secret);
    }

    [Fact]
    public async Task Client_SeesEveryTool()
    {
        await using var client = await ConnectAsync(RepositoryPaths.Root);

        var tools = await client.ListToolsAsync();

        tools.Select(tool => tool.Name).Should().Contain(["list_rules", "scan_path", "explain_rule"]);
    }

    [Fact]
    public async Task ScanPath_OutsideAllowedRoot_ReturnsToolError()
    {
        await using var client = await ConnectAsync(RepositoryPaths.VulnerableRepo);

        var response = await client.CallToolAsync(
            "scan_path",
            new Dictionary<string, object?> { ["path"] = RepositoryPaths.Root });

        response.IsError.Should().BeTrue();
        JsonSerializer.Serialize(response.Content, ModelContextProtocol.McpJsonUtilities.DefaultOptions)
            .Should().Contain("outside the allowed roots");
    }

    [Fact]
    public async Task InvalidAllowedRoot_ExitsWithErrorOnStderrAndNothingOnStdout()
    {
        using var cts = new CancellationTokenSource(Timeout);
        var missing = Path.Combine(RepositoryPaths.Root, "does-not-exist");
        using var server = StartServer("--allowed-root", missing);

        var stdout = server.StandardOutput.ReadToEndAsync(cts.Token);
        var stderr = server.StandardError.ReadToEndAsync(cts.Token);
        await server.WaitForExitAsync(cts.Token);

        server.ExitCode.Should().Be(Program.ExitConfigurationError);
        (await stdout).Should().BeEmpty();
        (await stderr).Should().Contain("Allowed root does not exist");
    }

    private static Process StartServer(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo(DotnetHost)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = RepositoryPaths.Root,
        };
        startInfo.ArgumentList.Add(ServerAssembly);
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        return Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start the server.");
    }

    // One JSON object per line, which is how the stdio transport frames messages.
    private static async Task SendAsync(Process server, object message)
    {
        await server.StandardInput.WriteLineAsync(JsonSerializer.Serialize(message));
        await server.StandardInput.FlushAsync();
    }

    private static Task<McpClient> ConnectAsync(string allowedRoot) =>
        McpClient.CreateAsync(new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "codesentinel",
            Command = DotnetHost,
            Arguments = [ServerAssembly, "--allowed-root", allowedRoot],
            WorkingDirectory = RepositoryPaths.Root,
        }));
}
