using CodeSentinel.Application.DependencyInjection;
using CodeSentinel.Infrastructure.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Mcp.Tests;

// The same services the server composes, without the MCP host or transport, so tool
// classes can be exercised directly.
internal static class TestServices
{
    public static ServiceProvider Build()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCodeSentinelApplication();
        services.AddCodeSentinelInfrastructure();
        return services.BuildServiceProvider();
    }
}
