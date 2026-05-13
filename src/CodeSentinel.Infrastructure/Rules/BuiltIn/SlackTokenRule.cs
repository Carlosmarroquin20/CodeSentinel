using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Infrastructure.Rules.BuiltIn;

internal sealed class SlackTokenRule : RegexDetectionRule
{
    // Bot (xoxb), user (xoxp), legacy (xoxa, xoxs, xoxr, xoxo), and app-level (xapp) tokens.
    // Format varies in number of dash-separated segments (xoxb has 3, xoxp has 4, xapp has 4
    // including a leading version marker), so the pattern matches an alphanumeric-and-dash body
    // of at least 24 characters after the prefix. The distinctive prefix keeps false positives low.
    private static readonly Regex Pattern = new(
        @"\b(?:xox[bpoasr]|xapp)-[0-9A-Za-z][0-9A-Za-z-]{22,}\b",
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
