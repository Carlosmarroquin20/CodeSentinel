using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Infrastructure.Rules.BuiltIn;

internal sealed class StripeApiKeyRule : RegexDetectionRule
{
    // Secret (sk_) and restricted (rk_) keys for live and test modes. Publishable
    // keys (pk_) are intentionally excluded because they are designed to be public.
    private static readonly Regex Pattern = new(
        @"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        matchTimeout: TimeSpan.FromSeconds(1));

    public StripeApiKeyRule() : base(Pattern) { }

    public override RuleMetadata Metadata { get; } = new(
        Id: "CS008",
        Title: "Stripe Secret Key",
        Description: "A Stripe secret or restricted API key was detected. These credentials grant access to a Stripe account's payment infrastructure.",
        Category: RuleCategory.Secret,
        DefaultSeverity: Severity.Critical);
}
