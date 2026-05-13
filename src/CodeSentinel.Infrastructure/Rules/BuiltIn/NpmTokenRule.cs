using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Infrastructure.Rules.BuiltIn;

internal sealed class NpmTokenRule : RegexDetectionRule
{
    // npm registry tokens issued since 2021 follow the npm_<36 chars> shape.
    private static readonly Regex Pattern = new(
        @"\bnpm_[A-Za-z0-9]{36}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        matchTimeout: TimeSpan.FromSeconds(1));

    public NpmTokenRule() : base(Pattern) { }

    public override RuleMetadata Metadata { get; } = new(
        Id: "CS010",
        Title: "npm Access Token",
        Description: "An npm access token was detected. These credentials allow publishing or installing private packages on the npm registry.",
        Category: RuleCategory.Secret,
        DefaultSeverity: Severity.High);
}
