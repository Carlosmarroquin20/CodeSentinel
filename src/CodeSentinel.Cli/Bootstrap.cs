using CodeSentinel.Application.DependencyInjection;
using CodeSentinel.Infrastructure.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace CodeSentinel.Cli;

internal static class Bootstrap
{
    public static ServiceProvider BuildServiceProvider(LogLevel minimumLevel = LogLevel.Information)
    {
        var services = new ServiceCollection();

        services.AddLogging(builder =>
        {
            builder.SetMinimumLevel(minimumLevel);
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

    // Resolves the minimum log level from the raw CLI arguments before the command
    // parser runs. Done this way because the logger has to be configured at provider
    // construction time, which is earlier than System.CommandLine's invocation pipeline.
    // If both --verbose and --quiet are present, verbose wins because it is the more
    // explicit, debugging-oriented choice.
    public static LogLevel ResolveLogLevel(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        var verbose = false;
        var quiet = false;

        foreach (var arg in args)
        {
            if (arg is "--verbose" or "-v")
                verbose = true;
            else if (arg is "--quiet" or "-q")
                quiet = true;
        }

        if (verbose) return LogLevel.Debug;
        if (quiet) return LogLevel.Warning;
        return LogLevel.Information;
    }
}
