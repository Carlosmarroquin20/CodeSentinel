using CodeSentinel.Core.Findings;

namespace CodeSentinel.Core.Detection;

public interface IDetectionRule
{
    RuleMetadata Metadata { get; }

    ValueTask<IReadOnlyList<Finding>> AnalyzeAsync(ScannableFile file, CancellationToken cancellationToken);
}
