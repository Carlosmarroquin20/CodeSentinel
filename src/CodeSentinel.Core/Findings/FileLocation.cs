namespace CodeSentinel.Core.Findings;

public sealed record FileLocation(string FilePath, int LineNumber, int ColumnNumber, string? Snippet);
