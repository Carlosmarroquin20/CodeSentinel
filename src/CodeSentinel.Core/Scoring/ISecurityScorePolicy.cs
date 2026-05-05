using CodeSentinel.Core.Findings;

namespace CodeSentinel.Core.Scoring;

public interface ISecurityScorePolicy
{
    SecurityScore Compute(IReadOnlyCollection<Finding> findings, int filesScanned);
}
