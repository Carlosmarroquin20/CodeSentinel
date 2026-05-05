using CodeSentinel.Core.Findings;
using CodeSentinel.Core.Scoring;

namespace CodeSentinel.Core.Scanning;

public sealed record ScanResult(
    IReadOnlyList<Finding> Findings,
    int FilesScanned,
    TimeSpan Duration,
    SecurityScore Score)
{
    public static ScanResult Empty(SecurityScore score) =>
        new(Array.Empty<Finding>(), 0, TimeSpan.Zero, score);
}
