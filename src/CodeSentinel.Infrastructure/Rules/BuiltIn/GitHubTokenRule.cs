using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Infrastructure.Rules.BuiltIn;

internal sealed class GitHubTokenRule : RegexDetectionRule
{
    // Covers both classic GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_ followed by 36 alphanumerics)
    // and fine-grained personal access tokens (github_pat_ prefix, 82-char body with underscores).
    private static readonly Regex Pattern = new(
        @"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        matchTimeout: TimeSpan.FromSeconds(1));

    public GitHubTokenRule() : base(Pattern) { }

    public override RuleMetadata Metadata { get; } = new(
        Id: "CS006",
        Title: "GitHub Token",
        Description: "A GitHub personal access token, OAuth token, or fine-grained token was detected. These credentials grant API access to GitHub.",
        Category: RuleCategory.Secret,
        DefaultSeverity: Severity.Critical);
}
