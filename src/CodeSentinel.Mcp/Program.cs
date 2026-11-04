using CodeSentinel.Mcp.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CodeSentinel.Mcp;

internal static class Program
{
    public const int ExitConfigurationError = 1;

    public static async Task<int> Main(string[] args)
    {
        IHost host;
        try
        {
            host = McpServerHost.Build(args);
        }
        catch (ArgumentException ex)
        {
            // stdout belongs to the protocol even before the server starts.
            await Console.Error.WriteLineAsync($"codesentinel-mcp: {ex.Message}").ConfigureAwait(false);
            return ExitConfigurationError;
        }

        using (host)
        {
            var logger = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("codesentinel-mcp");
            var roots = host.Services.GetRequiredService<AllowedRoots>();
            logger.LogInformation("Allowed roots: {Roots}", string.Join(", ", roots.Paths));

            await host.RunAsync().ConfigureAwait(false);
        }

        return 0;
    }
}
