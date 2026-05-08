using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Infrastructure.Rules.BuiltIn;

internal sealed class AwsAccessKeyRule : RegexDetectionRule
{
    // AKIA = long-term key; ASIA = temporary STS token. Both are 20-character alphanumeric strings.
    private static readonly Regex Pattern = new(
        @"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        matchTimeout: TimeSpan.FromSeconds(1));

    public AwsAccessKeyRule() : base(Pattern) { }

    public override RuleMetadata Metadata { get; } = new(
        Id: "CS001",
        Title: "AWS Access Key ID",
        Description: "An AWS access key ID was detected. This credential provides access to AWS services.",
        Category: RuleCategory.Secret,
        DefaultSeverity: Severity.Critical);
}
