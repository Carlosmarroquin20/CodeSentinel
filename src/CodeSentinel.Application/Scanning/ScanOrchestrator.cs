using CodeSentinel.Application.Abstractions;
using CodeSentinel.Core.Findings;
using CodeSentinel.Core.Scanning;
using CodeSentinel.Core.Scoring;
using Microsoft.Extensions.Logging;

namespace CodeSentinel.Application.Scanning;

internal sealed class ScanOrchestrator : IScanOrchestrator
{
    private readonly ILogger<ScanOrchestrator> _logger;
    private readonly ISecurityScorePolicy _scorePolicy;

    public ScanOrchestrator(ILogger<ScanOrchestrator> logger, ISecurityScorePolicy scorePolicy)
    {
        _logger = logger;
        _scorePolicy = scorePolicy;
    }

    public Task<ScanResult> ExecuteAsync(ScanRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        // End-to-end wiring placeholder. Detection, file traversal, and reporting are introduced
        // in subsequent phases against the same orchestrator contract.
        _logger.LogInformation("Scan requested for {Path}", request.RootPath);

        var findings = Array.Empty<Finding>();
        var score = _scorePolicy.Compute(findings, filesScanned: 0);

        return Task.FromResult(ScanResult.Empty(score));
    }
}
