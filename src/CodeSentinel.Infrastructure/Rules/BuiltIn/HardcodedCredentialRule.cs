using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Infrastructure.Rules.BuiltIn;

internal sealed class HardcodedCredentialRule : RegexDetectionRule
{
    // Matches common credential key names assigned to a quoted non-trivial string.
    // Group 1 captures the secret value, which is redacted in the snippet while the key name remains visible.
    private static readonly Regex Pattern = new(
        @"(?i)(?:password|passwd|pwd|secret|api_key|apikey|token|access_key|client_secret)\s*[:=]\s*['""]([^'""]{8,})['""]",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        matchTimeout: TimeSpan.FromSeconds(1));

    public HardcodedCredentialRule() : base(Pattern) { }

    public override RuleMetadata Metadata { get; } = new(
        Id: "CS005",
        Title: "Hardcoded Credential",
        Description: "A credential or secret appears to be hardcoded in source code or configuration.",
        Category: RuleCategory.Secret,
        DefaultSeverity: Severity.High);
}
