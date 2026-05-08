using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Infrastructure.Rules.BuiltIn;

internal sealed class PrivateKeyRule : RegexDetectionRule
{
    // Matches PEM private key headers for RSA, EC, OpenSSH, DSA, PGP, and the generic PKCS#8 format.
    private static readonly Regex Pattern = new(
        @"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        matchTimeout: TimeSpan.FromSeconds(1));

    public PrivateKeyRule() : base(Pattern) { }

    public override RuleMetadata Metadata { get; } = new(
        Id: "CS003",
        Title: "Private Key",
        Description: "A PEM-encoded private key header was detected. Committing private keys exposes cryptographic material.",
        Category: RuleCategory.Secret,
        DefaultSeverity: Severity.Critical);
}
