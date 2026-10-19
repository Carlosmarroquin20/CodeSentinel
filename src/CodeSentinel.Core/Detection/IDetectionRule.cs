using CodeSentinel.Core.Findings;

namespace CodeSentinel.Core.Detection;

// The orchestrator calls AnalyzeAsync for many files at once from different threads
// (ADR 0007), so implementations must be stateless or otherwise thread-safe. Secret
// rules are expected to redact matched values in snippets and to set
// FileLocation.EndColumnNumber so overlapping matches can be consolidated (ADR 0008).
public interface IDetectionRule
{
    RuleMetadata Metadata { get; }

    ValueTask<IReadOnlyList<Finding>> AnalyzeAsync(ScannableFile file, CancellationToken cancellationToken);
}
