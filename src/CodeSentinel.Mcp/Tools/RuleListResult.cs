namespace CodeSentinel.Mcp.Tools;

// Severity and category are strings rather than enums so the JSON an agent receives
// reads "Critical" instead of 4.
internal sealed record RuleSummary(
    string Id,
    string Title,
    string Category,
    string Severity,
    string Description);

internal sealed record RuleListResult(
    int Count,
    IReadOnlyList<RuleSummary> Rules);

internal sealed record ExplainRuleResult(
    string Id,
    string Title,
    string Category,
    string Severity,
    string Summary,
    string Detects,
    string Risk,
    IReadOnlyList<string> Remediation,
    string Suppression);
