using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Infrastructure.Rules.BuiltIn;

internal sealed class PrivateKeyRule : RegexDetectionRule
{
    // Matches PEM private key headers for RSA, EC, OpenSSH, DSA, and PKCS#8 (plain and
    // encrypted), plus the ASCII-armored OpenPGP header, which ends in "KEY BLOCK-----".
    // An encrypted key is still reported: its passphrase is often weak or committed nearby.
    private static readonly Regex Pattern = new(
        @"-----BEGIN (?:(?:RSA|EC|OPENSSH|DSA|PGP|ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?-----",
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
