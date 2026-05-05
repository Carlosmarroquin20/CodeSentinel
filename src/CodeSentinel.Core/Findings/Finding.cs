namespace CodeSentinel.Core.Findings;

public sealed record Finding(
    string RuleId,
    string Title,
    string Description,
    Severity Severity,
    FileLocation Location,
    double Confidence);
