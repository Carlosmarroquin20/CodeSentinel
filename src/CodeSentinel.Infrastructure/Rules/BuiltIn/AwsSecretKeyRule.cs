using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Infrastructure.Rules.BuiltIn;

internal sealed class AwsSecretKeyRule : RegexDetectionRule
{
    // Targets common assignment forms for AWS secret access keys in config files and source code.
    // The value group (group 1) is what gets redacted; the key name preserves context in the snippet.
    private static readonly Regex Pattern = new(
        @"(?i)(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['""]?([A-Za-z0-9/+=]{40})['""]?",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        matchTimeout: TimeSpan.FromSeconds(1));

    public AwsSecretKeyRule() : base(Pattern) { }

    public override RuleMetadata Metadata { get; } = new(
        Id: "CS002",
        Title: "AWS Secret Access Key",
        Description: "An AWS secret access key was detected in an assignment expression.",
        Category: RuleCategory.Secret,
        DefaultSeverity: Severity.Critical);
}
