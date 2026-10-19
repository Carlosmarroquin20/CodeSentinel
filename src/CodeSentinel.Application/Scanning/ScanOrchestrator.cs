using System.Diagnostics;
using CodeSentinel.Application.Abstractions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;
using CodeSentinel.Core.Scanning;
using CodeSentinel.Core.Scoring;
using Microsoft.Extensions.Logging;

namespace CodeSentinel.Application.Scanning;

internal sealed class ScanOrchestrator : IScanOrchestrator
{
    private readonly IFileSource _fileSource;
    private readonly IRuleProvider _ruleProvider;
    private readonly ISecurityScorePolicy _scorePolicy;
    private readonly ILogger<ScanOrchestrator> _logger;

    public ScanOrchestrator(
        IFileSource fileSource,
        IRuleProvider ruleProvider,
        ISecurityScorePolicy scorePolicy,
        ILogger<ScanOrchestrator> logger)
    {
        _fileSource = fileSource;
        _ruleProvider = ruleProvider;
        _scorePolicy = scorePolicy;
        _logger = logger;
    }

    public async Task<ScanResult> ExecuteAsync(ScanRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        _logger.LogInformation("Starting scan for {Path}", request.RootPath);

        var sw = Stopwatch.StartNew();
        var findings = new List<Finding>();
        var filesScanned = 0;
        var rules = _ruleProvider.GetRules().ToList();

        // Rules are stateless and CPU-bound, so files are analysed concurrently, one per
        // core. The file source is still pulled sequentially, which keeps disk access
        // ordered and bounded.
        var parallelOptions = new ParallelOptions
        {
            CancellationToken = cancellationToken,
            MaxDegreeOfParallelism = Environment.ProcessorCount,
        };

        await Parallel.ForEachAsync(
            _fileSource.GetFilesAsync(request, cancellationToken),
            parallelOptions,
            async (file, token) =>
            {
                Interlocked.Increment(ref filesScanned);
                _logger.LogDebug("Scanning {RelativePath}", file.RelativePath);

                var fileFindings = await AnalyzeFileAsync(file, rules, token).ConfigureAwait(false);
                if (fileFindings.Count == 0)
                    return;

                lock (findings)
                    findings.AddRange(fileFindings);
            }).ConfigureAwait(false);

        // Completion order varies between runs; sort so results are reproducible.
        findings.Sort(FindingOrder.Instance);

        var secretRuleIds = rules
            .Where(r => r.Metadata.Category == RuleCategory.Secret)
            .Select(r => r.Metadata.Id)
            .ToHashSet(StringComparer.Ordinal);
        var consolidated = OverlappingSecretFilter.Apply(findings, secretRuleIds);

        sw.Stop();
        var score = _scorePolicy.Compute(consolidated, filesScanned);

        _logger.LogInformation(
            "Scan completed. Files: {FilesScanned}, Findings: {FindingCount}, Score: {Score} ({Grade}), Duration: {Duration}ms",
            filesScanned, consolidated.Count, score.Value, score.Grade, (long)sw.Elapsed.TotalMilliseconds);

        return new ScanResult(consolidated.AsReadOnly(), filesScanned, sw.Elapsed, score);
    }

    private async Task<List<Finding>> AnalyzeFileAsync(
        ScannableFile file,
        IReadOnlyList<IDetectionRule> rules,
        CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        foreach (var rule in rules)
        {
            try
            {
                var ruleFindings = await rule.AnalyzeAsync(file, cancellationToken).ConfigureAwait(false);
                findings.AddRange(ruleFindings);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // One misbehaving rule (for example a regex hitting its match timeout on
                // a pathological line) must not abort the whole scan.
                _logger.LogWarning(ex, "Rule {RuleId} failed on {RelativePath}; skipping", rule.Metadata.Id, file.RelativePath);
            }
        }

        return findings;
    }

    private sealed class FindingOrder : IComparer<Finding>
    {
        public static FindingOrder Instance { get; } = new();

        public int Compare(Finding? x, Finding? y)
        {
            if (ReferenceEquals(x, y))
                return 0;
            if (x is null)
                return -1;
            if (y is null)
                return 1;

            var result = string.CompareOrdinal(x.Location.FilePath, y.Location.FilePath);
            if (result == 0)
                result = x.Location.LineNumber.CompareTo(y.Location.LineNumber);
            if (result == 0)
                result = x.Location.ColumnNumber.CompareTo(y.Location.ColumnNumber);
            if (result == 0)
                result = string.CompareOrdinal(x.RuleId, y.RuleId);

            return result;
        }
    }
}
