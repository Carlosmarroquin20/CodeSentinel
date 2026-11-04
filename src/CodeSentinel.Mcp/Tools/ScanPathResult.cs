namespace CodeSentinel.Mcp.Tools;

internal sealed record ScanPathResult(
    string Path,
    int FilesScanned,
    int Score,
    string Grade,
    SeverityCounts FindingsBySeverity,
    int TotalFindings,
    int MatchingFindings,
    int ReturnedFindings,
    bool Truncated,
    IReadOnlyList<FindingSummary> Findings);

internal sealed record SeverityCounts(
    int Critical,
    int High,
    int Medium,
    int Low,
    int Info);

// File paths are relative to the scanned directory and always use forward slashes, so
// the agent sees the same value on every platform. Snippets come from the rules, which
// replace secret values with [REDACTED] (ADR 0003).
internal sealed record FindingSummary(
    string RuleId,
    string Severity,
    string File,
    int Line,
    int Column,
    string Message,
    string? Snippet,
    double Confidence);
