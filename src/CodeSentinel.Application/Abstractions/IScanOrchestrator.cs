using CodeSentinel.Core.Scanning;

namespace CodeSentinel.Application.Abstractions;

public interface IScanOrchestrator
{
    Task<ScanResult> ExecuteAsync(ScanRequest request, CancellationToken cancellationToken);
}
