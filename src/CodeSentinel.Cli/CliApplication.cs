using System.CommandLine;
using CodeSentinel.Application.Abstractions;
using CodeSentinel.Application.Security;
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
    private const string IgnoreFileName = IIgnoreFileReader.FileName;

    // Ctrl+C and SIGTERM cancel the token passed to the scan. System.CommandLine then
    // waits this long for the action to finish before ending the process (2 seconds by
    // default). Aborting a remote clone and deleting its temporary directory can take
    // longer than that (ADR 0006).
    private static readonly TimeSpan ProcessTerminationTimeout = TimeSpan.FromSeconds(10);

    public static async Task<int> RunAsync(
        string[] args,
        IServiceProvider services,
        CancellationToken cancellationToken = default)
    {
        var targetArgument = new Argument<string>("target")
        {
            Description = "Local repository path or Git remote URL "
                        + "(https://..., git@..., ssh://..., or git://...).",
        };

        var formatOption = new Option<string?>("--format", "-f")
        {
            Description = "Report format (json, html, sarif). Inferred from --output extension when omitted; "
                        + "defaults to json.",
        };

        var outputOption = new Option<FileInfo?>("--output", "-o")
        {
            Description = "Write the scan report to this path. If omitted, no report file is generated.",
        };

        var failOnOption = new Option<Severity?>("--fail-on")
        {
            Description = "Minimum severity (Info, Low, Medium, High, Critical) that triggers exit code 1. "
                        + "If omitted, any finding causes exit code 1.",
        };

        var excludeOption = new Option<string[]>("--exclude", "-e")
        {
            Description = "Glob pattern to exclude from the scan. Repeatable. Combined with patterns from "
                        + IgnoreFileName + " in the scan root, if present.",
            AllowMultipleArgumentsPerToken = true,
        };

        var noIgnoreFileOption = new Option<bool>("--no-ignore-file")
        {
            Description = "Do not read " + IgnoreFileName + " from the scan root. Use this when scanning "
                        + "repositories you do not control, whose ignore file could hide files from the scan.",
        };

        var noInlineIgnoreOption = new Option<bool>("--no-inline-ignore")
        {
            Description = "Report findings even on lines marked with a codesentinel:ignore comment. "
                        + "Use this when scanning repositories you do not control.",
        };

        // --verbose and --quiet are applied at Bootstrap time (before the parser runs).
        // They are declared here so they appear in --help, and are recursive so every
        // subcommand accepts them instead of reporting an unknown argument.
        var verboseOption = new Option<bool>("--verbose", "-v")
        {
            Description = "Show debug-level log output, including per-file scan progress.",
            Recursive = true,
        };

        var quietOption = new Option<bool>("--quiet", "-q")
        {
            Description = "Suppress informational log output. Warnings and errors are still shown.",
            Recursive = true,
        };

        var rootCommand = new RootCommand("CodeSentinel - security scanner for source repositories.")
        {
            targetArgument,
            formatOption,
            outputOption,
            failOnOption,
            excludeOption,
            noIgnoreFileOption,
            noInlineIgnoreOption,
            verboseOption,
            quietOption,
        };

        rootCommand.SetAction(async (parseResult, invocationToken) =>
        {
            var target = parseResult.GetValue(targetArgument)!;
            var options = new ScanOptions(
                Format: parseResult.GetValue(formatOption),
                Output: parseResult.GetValue(outputOption),
                FailOn: parseResult.GetValue(failOnOption),
                Excludes: parseResult.GetValue(excludeOption) ?? [],
                UseIgnoreFile: !parseResult.GetValue(noIgnoreFileOption),
                HonorInlineSuppressions: !parseResult.GetValue(noInlineIgnoreOption));

            // The invocation token fires on Ctrl+C; the caller's token is still honoured so
            // tests and hosts can cancel programmatically.
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, invocationToken);

            return await RunScanSafelyAsync(target, options, services, linked.Token).ConfigureAwait(false);
        });

        var listRulesCommand = new Command("list-rules", "List all detection rules registered in the scanner.");
        listRulesCommand.SetAction(_ => ExecuteListRules(services, Console.Out));
        rootCommand.Subcommands.Add(listRulesCommand);

        // RootCommand adds --help and --version, and the default invocation reports parse
        // errors and handles Ctrl+C. --version short-circuits before the target argument
        // is validated, so `codesentinel --version` works without a target.
        var configuration = new InvocationConfiguration
        {
            ProcessTerminationTimeout = ProcessTerminationTimeout,
        };

        return await rootCommand.Parse(args).InvokeAsync(configuration, cancellationToken).ConfigureAwait(false);
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

    // Exit code 1 is reserved for "findings above threshold", so CI pipelines can tell a
    // dirty repository from a broken scan. Anything that escapes the scan pipeline is
    // reported as a scan error (2) instead of falling through to System.CommandLine's
    // default exception handler, which would also return 1.
    private static async Task<int> RunScanSafelyAsync(
        string target,
        ScanOptions options,
        IServiceProvider services,
        CancellationToken cancellationToken)
    {
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("codesentinel");

        try
        {
            return await RunScanAsync(target, options, services, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning("Scan cancelled.");
            return ExitScanError;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Scan failed unexpectedly.");
            return ExitScanError;
        }
    }

    // Top-level dispatch: clone first if the target is a Git URL, otherwise scan the
    // local path directly. The cloned working copy is disposed after the scan so the
    // temp directory does not linger.
    private static async Task<int> RunScanAsync(
        string target,
        ScanOptions options,
        IServiceProvider services,
        CancellationToken cancellationToken)
    {
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("codesentinel");

        if (LooksLikeGitUrl(target))
        {
            var safeTarget = UrlRedaction.RedactUserInfo(target);
            IClonedRepository cloned;
            try
            {
                var cloner = services.GetRequiredService<IRepositoryCloner>();
                cloned = await cloner.CloneAsync(target, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to clone {Url}", safeTarget);
                return ExitScanError;
            }

            await using (cloned.ConfigureAwait(false))
            {
                return await ExecuteScanAsync(
                    new DirectoryInfo(cloned.LocalPath),
                    displayTarget: safeTarget,
                    options, services, logger, cancellationToken).ConfigureAwait(false);
            }
        }

        var path = new DirectoryInfo(target);
        return await ExecuteScanAsync(
            path,
            displayTarget: path.FullName,
            options, services, logger, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<int> ExecuteScanAsync(
        DirectoryInfo path,
        string displayTarget,
        ScanOptions options,
        IServiceProvider services,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        if (!path.Exists)
        {
            logger.LogError("Path does not exist: {Path}", path.FullName);
            return ExitScanError;
        }

        var ignoreGlobs = GatherIgnoreGlobs(path, options, services, logger);
        var orchestrator = services.GetRequiredService<IScanOrchestrator>();
        var request = new ScanRequest(path.FullName, ignoreGlobs, options.HonorInlineSuppressions);
        var result = await orchestrator.ExecuteAsync(request, cancellationToken).ConfigureAwait(false);

        logger.LogInformation(
            "Scan completed. Files: {FilesScanned}, Findings: {FindingCount}, Score: {Score} ({Grade})",
            result.FilesScanned,
            result.Findings.Count,
            result.Score.Value,
            result.Score.Grade);

        if (options.Output is not null)
        {
            var reportExit = await TryWriteReportAsync(result, displayTarget, options.Format, options.Output, services, logger, cancellationToken)
                .ConfigureAwait(false);
            if (reportExit != ExitSuccess)
                return reportExit;
        }

        return ComputeFindingsExitCode(result.Findings, options.FailOn, logger);
    }

    internal static bool LooksLikeGitUrl(string target) =>
        target.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
        target.StartsWith("http://",  StringComparison.OrdinalIgnoreCase) ||
        target.StartsWith("git://",   StringComparison.OrdinalIgnoreCase) ||
        target.StartsWith("ssh://",   StringComparison.OrdinalIgnoreCase) ||
        target.StartsWith("git@",     StringComparison.OrdinalIgnoreCase);

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
        string displayTarget,
        string? requestedFormat,
        FileInfo output,
        IServiceProvider services,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var resolvedFormat = requestedFormat ?? InferFormatFromExtension(output) ?? DefaultFormat;
        var reportService = services.GetRequiredService<IReportService>();
        var report = new ScanReport(
            TargetPath: displayTarget,
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
            ".sarif" => "sarif",
            _ => null,
        };

    private static List<string> GatherIgnoreGlobs(
        DirectoryInfo scanRoot,
        ScanOptions options,
        IServiceProvider services,
        ILogger logger)
    {
        var globs = new List<string>(options.Excludes);

        if (!options.UseIgnoreFile)
        {
            if (File.Exists(Path.Combine(scanRoot.FullName, IgnoreFileName)))
                logger.LogInformation("Ignoring {File} because --no-ignore-file was given", IgnoreFileName);
            return globs;
        }

        var reader = services.GetRequiredService<IIgnoreFileReader>();
        globs.AddRange(reader.ReadPatterns(scanRoot.FullName));
        return globs;
    }

    private sealed record ScanOptions(
        string? Format,
        FileInfo? Output,
        Severity? FailOn,
        IReadOnlyList<string> Excludes,
        bool UseIgnoreFile,
        bool HonorInlineSuppressions);

    private static string GetScannerVersion() =>
        typeof(CliApplication).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
}
