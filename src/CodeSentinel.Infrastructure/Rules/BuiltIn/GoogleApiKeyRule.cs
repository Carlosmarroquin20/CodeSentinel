using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Infrastructure.Rules.BuiltIn;

internal sealed class GoogleApiKeyRule : RegexDetectionRule
{
    // Google API keys follow a stable 39-character format: AIza + 35 chars of [A-Za-z0-9_-].
    private static readonly Regex Pattern = new(
        @"\bAIza[0-9A-Za-z_-]{35}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        matchTimeout: TimeSpan.FromSeconds(1));

    public GoogleApiKeyRule() : base(Pattern) { }

    public override RuleMetadata Metadata { get; } = new(
        Id: "CS009",
        Title: "Google API Key",
        Description: "A Google Cloud API key was detected. These credentials grant access to Google services such as Maps, Translate, or GCP APIs.",
        Category: RuleCategory.Secret,
        DefaultSeverity: Severity.High);
}
