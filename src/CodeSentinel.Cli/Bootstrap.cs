using CodeSentinel.Application.DependencyInjection;
using CodeSentinel.Infrastructure.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace CodeSentinel.Cli;

internal static class Bootstrap
{
    public static ServiceProvider BuildServiceProvider()
    {
        var services = new ServiceCollection();

        services.AddLogging(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Information);
            builder.AddSimpleConsole(options =>
            {
                options.SingleLine = true;
                options.TimestampFormat = "HH:mm:ss ";
            });
        });

        services.AddCodeSentinelApplication();
        services.AddCodeSentinelInfrastructure();

        return services.BuildServiceProvider();
    }
}
