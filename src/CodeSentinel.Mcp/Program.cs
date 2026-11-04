using Microsoft.Extensions.Hosting;

namespace CodeSentinel.Mcp;

internal static class Program
{
    public static async Task Main(string[] args)
    {
        using var host = McpServerHost.Build(args);
        await host.RunAsync().ConfigureAwait(false);
    }
}
