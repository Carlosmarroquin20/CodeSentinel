using CodeSentinel.Application.DependencyInjection;
using CodeSentinel.Infrastructure.DependencyInjection;
using CodeSentinel.Mcp.Security;
using CodeSentinel.Mcp.Tools;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;

namespace CodeSentinel.Mcp;

internal static class McpServerHost
{
    // Throws ArgumentException when the arguments or the allowed roots are invalid.
    //
    // The empty builder is used on purpose: the default one reads appsettings.json and
    // environment variables from the working directory, which is usually the repository
    // the agent is working on, and adds a console logger that writes to stdout. With the
    // stdio transport stdout carries the protocol, so every log line goes to stderr.
    public static IHost Build(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        var workingDirectory = Directory.GetCurrentDirectory();
        var allowedRoots = AllowedRoots.Parse(
            args,
            Environment.GetEnvironmentVariable(AllowedRoots.EnvironmentVariable),
            workingDirectory);

        var builder = Host.CreateEmptyApplicationBuilder(new HostApplicationBuilderSettings
        {
            ContentRootPath = workingDirectory,
        });

        builder.Logging.SetMinimumLevel(LogLevel.Information);
        builder.Logging.AddSimpleConsole(options =>
        {
            options.SingleLine = true;
            options.TimestampFormat = "HH:mm:ss ";
        });
        builder.Services.Configure<ConsoleLoggerOptions>(options =>
            options.LogToStandardErrorThreshold = LogLevel.Trace);
        builder.Services.Configure<ConsoleLifetimeOptions>(options => options.SuppressStatusMessages = true);

        builder.Services.AddCodeSentinelApplication();
        builder.Services.AddCodeSentinelInfrastructure();
        builder.Services.AddSingleton(allowedRoots);
        builder.Services.AddSingleton<ScanPathValidator>();

        builder.Services
            .AddMcpServer(options =>
            {
                options.ServerInfo = new() { Name = "codesentinel", Version = GetServerVersion() };
                options.ServerInstructions = ServerInstructions;
            })
            .WithStdioServerTransport()
            .WithTools<RuleTools>()
            .WithTools<ScanTools>();

        return builder.Build();
    }

    private const string ServerInstructions =
        "CodeSentinel is a read-only security scanner for local source code. Call scan_path on a "
        + "directory to get a security score and the secrets or insecure patterns it contains; secret "
        + "values are always redacted. Call list_rules to see what can be detected. Only directories "
        + "inside the allowed roots configured when the server was started can be scanned.";

    private static string GetServerVersion() =>
        typeof(McpServerHost).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
}
