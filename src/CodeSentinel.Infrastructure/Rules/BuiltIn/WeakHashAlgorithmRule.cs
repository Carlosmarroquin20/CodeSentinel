using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Infrastructure.Rules.BuiltIn;

internal sealed class WeakHashAlgorithmRule : RegexDetectionRule
{
    // Covers MD5 and SHA-1 usage across .NET, Python, and Java — the most common runtimes
    // where this mistake appears in security-relevant contexts.
    private static readonly Regex Pattern = new(
        @"(?i)(?:" +
        @"MD5\.Create\(\)|new\s+MD5CryptoServiceProvider\s*\(\)|SHA1\.Create\(\)|" +
        @"hashlib\.(?:md5|sha1)\s*\(|" +
        @"MessageDigest\.getInstance\s*\(\s*['""](?:MD5|SHA-1|SHA1)['""])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        matchTimeout: TimeSpan.FromSeconds(1));

    public WeakHashAlgorithmRule() : base(Pattern) { }

    public override RuleMetadata Metadata { get; } = new(
        Id: "CS101",
        Title: "Weak Hash Algorithm",
        Description: "MD5 or SHA-1 usage was detected. These algorithms are cryptographically broken and must not be used for security-sensitive operations.",
        Category: RuleCategory.InsecurePattern,
        DefaultSeverity: Severity.Medium);
}
