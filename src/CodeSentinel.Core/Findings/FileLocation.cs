namespace CodeSentinel.Core.Findings;

// Columns are 1-based. EndColumnNumber, when known, points one past the last character
// of the match (the same convention SARIF uses for region.endColumn).
public sealed record FileLocation(
    string FilePath,
    int LineNumber,
    int ColumnNumber,
    string? Snippet,
    int? EndColumnNumber = null);
