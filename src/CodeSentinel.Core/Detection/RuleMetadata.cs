using CodeSentinel.Core.Findings;

namespace CodeSentinel.Core.Detection;

public sealed record RuleMetadata(
    string Id,
    string Title,
    string Description,
    RuleCategory Category,
    Severity DefaultSeverity);
