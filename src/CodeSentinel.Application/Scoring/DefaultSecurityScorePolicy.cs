using CodeSentinel.Core.Findings;
using CodeSentinel.Core.Scoring;

namespace CodeSentinel.Application.Scoring;

internal sealed class DefaultSecurityScorePolicy : ISecurityScorePolicy
{
    public SecurityScore Compute(IReadOnlyCollection<Finding> findings, int filesScanned)
    {
        if (findings.Count == 0)
        {
            return SecurityScore.Perfect;
        }

        var penalty = 0;
        foreach (var finding in findings)
        {
            penalty += finding.Severity switch
            {
                Severity.Critical => 25,
                Severity.High => 15,
                Severity.Medium => 8,
                Severity.Low => 3,
                _ => 1,
            };
        }

        var value = Math.Clamp(100 - penalty, 0, 100);
        var grade = value switch
        {
            >= 90 => "A",
            >= 75 => "B",
            >= 60 => "C",
            >= 40 => "D",
            _ => "F",
        };

        return new SecurityScore(value, grade);
    }
}
