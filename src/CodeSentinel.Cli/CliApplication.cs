using System.CommandLine;
using CodeSentinel.Application.Abstractions;
using CodeSentinel.Core.Findings;
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
    private const string IgnoreFileName = ".codesentinelignore";

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

        var failOnOption = new Option<Severity?>(
            aliases: ["--fail-on"],
            description: "Minimum severity (Info, Low, Medium, High, Critical) that triggers exit code 1. "
                       + "If omitted, any finding causes exit code 1.");

        var excludeOption = new Option<string[]>(
            aliases: ["--exclude", "-e"],
            description: "Glob pattern to exclude from the scan. Repeatable. Combined with patterns from "
                       + IgnoreFileName + " in the scan root, if present.")
        {
            AllowMultipleArgumentsPerToken = true,
        };

        var rootCommand = new RootCommand("CodeSentinel - security scanner for source repositories.")
        {
            pathArgument,
            formatOption,
            outputOption,
            failOnOption,
            excludeOption,
        };

        var exitCode = ExitSuccess;
        rootCommand.SetHandler(
            async (context) =>
            {
                var path = context.ParseResult.GetValueForArgument(pathArgument);
                var format = context.ParseResult.GetValueForOption(formatOption);
                var output = context.ParseResult.GetValueForOption(outputOption);
                var failOn = context.ParseResult.GetValueForOption(failOnOption);
                var excludes = context.ParseResult.GetValueForOption(excludeOption) ?? [];

                exitCode = await ExecuteScanAsync(
                    path, format, output, failOn, excludes, services, cancellationToken).ConfigureAwait(false);
            });

        var listRulesCommand = new Command("list-rules", "List all detection rules registered in the scanner.");
        listRulesCommand.SetHandler(context =>
        {
            exitCode = ExecuteListRules(services, Console.Out);
            return Task.CompletedTask;
        });
        rootCommand.AddCommand(listRulesCommand);

        var parseExit = await rootCommand.InvokeAsync(args).ConfigureAwait(false);
        return parseExit != 0 ? parseExit : exitCode;
    }

    private static int ExecuteListRules(IServiceProvider services, TextWriter output)
    {
        var ruleProvider = services.GetRequiredService<IRuleProvider>();
        var rules = ruleProvider.GetRules()
            .Select(r => r.Metadata)
            .OrderBy(m => m.Id, StringComparer.Ordinal)
            .ToList();

        if (rules.Count == 0)
        {
            output.WriteLine("No rules registered.");
            return ExitSuccess;
        }

        // Width each column to fit its longest value so the table stays aligned across runs.
        var idWidth       = Math.Max("ID".Length,       rules.Max(r => r.Id.Length));
        var severityWidth = Math.Max("SEVERITY".Length, rules.Max(r => r.DefaultSeverity.ToString().Length));
        var categoryWidth = Math.Max("CATEGORY".Length, rules.Max(r => r.Category.ToString().Length));

        const int ColumnGap = 2;
        var gap = new string(' ', ColumnGap);

        output.WriteLine($"{"ID".PadRight(idWidth)}{gap}{"SEVERITY".PadRight(severityWidth)}{gap}{"CATEGORY".PadRight(categoryWidth)}{gap}TITLE");

        foreach (var rule in rules)
        {
            output.WriteLine(
                $"{rule.Id.PadRight(idWidth)}{gap}" +
                $"{rule.DefaultSeverity.ToString().PadRight(severityWidth)}{gap}" +
                $"{rule.Category.ToString().PadRight(categoryWidth)}{gap}" +
                $"{rule.Title}");
        }

        return ExitSuccess;
    }

    private static async Task<int> ExecuteScanAsync(
        DirectoryInfo path,
        string? format,
        FileInfo? output,
        Severity? failOn,
        IReadOnlyList<string> cliExcludes,
        IServiceProvider services,
        CancellationToken cancellationToken)
    {
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("codesentinel");

        if (!path.Exists)
        {
            logger.LogError("Path does not exist: {Path}", path.FullName);
            return ExitScanError;
        }

        var ignoreGlobs = GatherIgnoreGlobs(path, cliExcludes, logger);
        var orchestrator = services.GetRequiredService<IScanOrchestrator>();
        var request = new ScanRequest(path.FullName, ignoreGlobs);
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

        return ComputeFindingsExitCode(result.Findings, failOn, logger);
    }

    private static int ComputeFindingsExitCode(IReadOnlyList<Finding> findings, Severity? threshold, ILogger logger)
    {
        if (threshold is null)
            return findings.Count == 0 ? ExitSuccess : ExitFindingsAboveThreshold;

        var blocking = findings.Count(f => f.Severity >= threshold.Value);
        if (blocking > 0)
        {
            logger.LogInformation(
                "{Count} finding(s) at or above {Threshold} - failing the scan.",
                blocking,
                threshold.Value);
            return ExitFindingsAboveThreshold;
        }

        // Findings exist but none breach the threshold; treat as a passing scan.
        logger.LogInformation(
            "No findings at or above {Threshold} - scan passed under the configured threshold.",
            threshold.Value);
        return ExitSuccess;
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

    private static List<string> GatherIgnoreGlobs(
        DirectoryInfo scanRoot,
        IReadOnlyList<string> cliExcludes,
        ILogger logger)
    {
        var globs = new List<string>(cliExcludes);
        var ignoreFile = new FileInfo(Path.Combine(scanRoot.FullName, IgnoreFileName));

        if (!ignoreFile.Exists)
            return globs;

        try
        {
            var fromFile = File.ReadAllLines(ignoreFile.FullName)
                .Select(line => line.Trim())
                .Where(line => line.Length > 0 && !line.StartsWith('#'))
                .ToList();

            if (fromFile.Count > 0)
            {
                globs.AddRange(fromFile);
                logger.LogInformation("Loaded {Count} pattern(s) from {File}", fromFile.Count, IgnoreFileName);
            }
        }
        catch (IOException ex)
        {
            logger.LogWarning(ex, "Could not read {File}; proceeding without it", IgnoreFileName);
        }

        return globs;
    }

    private static string GetScannerVersion() =>
        typeof(CliApplication).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
}
