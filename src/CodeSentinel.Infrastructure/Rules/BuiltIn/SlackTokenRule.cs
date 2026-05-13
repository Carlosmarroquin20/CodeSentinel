using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Infrastructure.Rules.BuiltIn;

internal sealed class SlackTokenRule : RegexDetectionRule
{
    // Bot (xoxb), user (xoxp), legacy (xoxa, xoxs), and app-level (xapp) tokens.
    // All share the xox[bpoas]- or xapp- prefix followed by dash-separated alphanumeric segments.
    private static readonly Regex Pattern = new(
        @"\b(?:xox[bpoas]|xapp)-[0-9A-Za-z]{10,}-[0-9A-Za-z-]{10,}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        matchTimeout: TimeSpan.FromSeconds(1));

    public SlackTokenRule() : base(Pattern) { }

    public override RuleMetadata Metadata { get; } = new(
        Id: "CS007",
        Title: "Slack Token",
        Description: "A Slack API token was detected. These credentials grant access to a Slack workspace's data and messaging.",
        Category: RuleCategory.Secret,
        DefaultSeverity: Severity.Critical);
}
