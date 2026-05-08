using System.CommandLine;
using CodeSentinel.Application.Abstractions;
using CodeSentinel.Core.Reporting;
using CodeSentinel.Core.Scanning;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace CodeSentinel.Cli;

internal static class CliApplication
{
    public const int ExitSuccess = 0;
    public const int ExitFindingsAboveThreshold = 1;
    public const int ExitScanError = 2;

    private const string DefaultFormat = "json";

    public static async Task<int> RunAsync(
        string[] args,
        IServiceProvider services,
        CancellationToken cancellationToken = default)
    {
        var pathArgument = new Argument<DirectoryInfo>(
            name: "path",
            description: "Repository root to scan.");

        var formatOption = new Option<string?>(
            aliases: ["--format", "-f"],
            description: "Report format (json, html). Inferred from --output extension when omitted; defaults to json.");

        var outputOption = new Option<FileInfo?>(
            aliases: ["--output", "-o"],
            description: "Write the scan report to this path. If omitted, no report file is generated.");

        var rootCommand = new RootCommand("CodeSentinel - security scanner for source repositories.")
        {
            pathArgument,
            formatOption,
            outputOption,
        };

        var exitCode = ExitSuccess;
        rootCommand.SetHandler(
            async (DirectoryInfo path, string? format, FileInfo? output) =>
            {
                exitCode = await ExecuteScanAsync(path, format, output, services, cancellationToken).ConfigureAwait(false);
            },
            pathArgument, formatOption, outputOption);

        var parseExit = await rootCommand.InvokeAsync(args).ConfigureAwait(false);
        return parseExit != 0 ? parseExit : exitCode;
    }

    private static async Task<int> ExecuteScanAsync(
        DirectoryInfo path,
        string? format,
        FileInfo? output,
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

        if (output is not null)
        {
            var reportExit = await TryWriteReportAsync(result, path, format, output, services, logger, cancellationToken)
                .ConfigureAwait(false);
            if (reportExit != ExitSuccess)
                return reportExit;
        }

        return result.Findings.Count == 0 ? ExitSuccess : ExitFindingsAboveThreshold;
    }

    private static async Task<int> TryWriteReportAsync(
        ScanResult result,
        DirectoryInfo target,
        string? requestedFormat,
        FileInfo output,
        IServiceProvider services,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var resolvedFormat = requestedFormat ?? InferFormatFromExtension(output) ?? DefaultFormat;
        var reportService = services.GetRequiredService<IReportService>();
        var report = new ScanReport(
            TargetPath: target.FullName,
            ScannedAt: DateTimeOffset.UtcNow,
            ScannerVersion: GetScannerVersion(),
            Result: result);

        try
        {
            await reportService.WriteReportAsync(report, output.FullName, resolvedFormat, cancellationToken)
                .ConfigureAwait(false);
            logger.LogInformation("Report written to {Path} ({Format})", output.FullName, resolvedFormat);
            return ExitSuccess;
        }
        catch (NotSupportedException ex)
        {
            logger.LogError("{Message}", ex.Message);
            return ExitScanError;
        }
        catch (IOException ex)
        {
            logger.LogError(ex, "Failed to write report to {Path}", output.FullName);
            return ExitScanError;
        }
    }

    private static string? InferFormatFromExtension(FileInfo file) =>
        file.Extension.ToLowerInvariant() switch
        {
            ".json" => "json",
            ".html" or ".htm" => "html",
            _ => null,
        };

    private static string GetScannerVersion() =>
        typeof(CliApplication).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
}
