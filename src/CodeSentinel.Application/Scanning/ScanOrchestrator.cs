using System.Diagnostics;
using CodeSentinel.Application.Abstractions;
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

        await foreach (var file in _fileSource.GetFilesAsync(request, cancellationToken).ConfigureAwait(false))
        {
            filesScanned++;
            _logger.LogDebug("Scanning {RelativePath}", file.RelativePath);
            foreach (var rule in rules)
            {
                var ruleFindings = await rule.AnalyzeAsync(file, cancellationToken).ConfigureAwait(false);
                findings.AddRange(ruleFindings);
            }
        }

        sw.Stop();
        var score = _scorePolicy.Compute(findings, filesScanned);

        _logger.LogInformation(
            "Scan completed. Files: {FilesScanned}, Findings: {FindingCount}, Score: {Score} ({Grade}), Duration: {Duration}ms",
            filesScanned, findings.Count, score.Value, score.Grade, (long)sw.Elapsed.TotalMilliseconds);

        return new ScanResult(findings.AsReadOnly(), filesScanned, sw.Elapsed, score);
    }
}
