using System.CommandLine;
using CodeSentinel.Application.Abstractions;
using CodeSentinel.Core.Scanning;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace CodeSentinel.Cli;

internal static class CliApplication
{
    public const int ExitSuccess = 0;
    public const int ExitFindingsAboveThreshold = 1;
    public const int ExitScanError = 2;

    public static async Task<int> RunAsync(
        string[] args,
        IServiceProvider services,
        CancellationToken cancellationToken = default)
    {
        var pathArgument = new Argument<DirectoryInfo>(
            name: "path",
            description: "Repository root to scan.");

        var rootCommand = new RootCommand("CodeSentinel - security scanner for source repositories.")
        {
            pathArgument,
        };

        var exitCode = ExitSuccess;
        rootCommand.SetHandler(
            async (DirectoryInfo path) =>
            {
                exitCode = await ExecuteScanAsync(path, services, cancellationToken).ConfigureAwait(false);
            },
            pathArgument);

        var parseExit = await rootCommand.InvokeAsync(args).ConfigureAwait(false);
        return parseExit != 0 ? parseExit : exitCode;
    }

    private static async Task<int> ExecuteScanAsync(
        DirectoryInfo path,
        IServiceProvider services,
        CancellationToken cancellationToken)
    {
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("codesentinel");

        if (!path.Exists)
        {
            logger.LogError("Path does not exist: {Path}", path.FullName);
            return ExitScanError;
        }

        var orchestrator = services.GetRequiredService<IScanOrchestrator>();
        var request = ScanRequest.ForPath(path.FullName);
        var result = await orchestrator.ExecuteAsync(request, cancellationToken).ConfigureAwait(false);

        logger.LogInformation(
            "Scan completed. Files: {FilesScanned}, Findings: {FindingCount}, Score: {Score} ({Grade})",
            result.FilesScanned,
            result.Findings.Count,
            result.Score.Value,
            result.Score.Grade);

        return result.Findings.Count == 0 ? ExitSuccess : ExitFindingsAboveThreshold;
    }
}
