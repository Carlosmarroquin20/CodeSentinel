using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Infrastructure.Rules.BuiltIn;

internal sealed class JwtTokenRule : RegexDetectionRule
{
    // Matches compact JWS (JWT) tokens: Base64Url(header).Base64Url(payload).Base64Url(signature).
    // Minimum group lengths reduce false positives from unrelated dot-separated identifiers.
    private static readonly Regex Pattern = new(
        @"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        matchTimeout: TimeSpan.FromSeconds(1));

    public JwtTokenRule() : base(Pattern) { }

    public override RuleMetadata Metadata { get; } = new(
        Id: "CS004",
        Title: "JSON Web Token",
        Description: "A JWT was detected. Hardcoded tokens can expose user sessions or service-to-service credentials.",
        Category: RuleCategory.Secret,
        DefaultSeverity: Severity.High);
}
