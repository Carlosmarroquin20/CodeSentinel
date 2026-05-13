using CodeSentinel.Application.Abstractions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Infrastructure.Rules.BuiltIn;
using CodeSentinel.Infrastructure.Rules.Heuristics;

namespace CodeSentinel.Infrastructure.Rules;

internal sealed class BuiltInRuleProvider : IRuleProvider
{
    private readonly IReadOnlyList<IDetectionRule> _rules;

    public BuiltInRuleProvider()
    {
        _rules = new List<IDetectionRule>
        {
            new AwsAccessKeyRule(),
            new AwsSecretKeyRule(),
            new PrivateKeyRule(),
            new JwtTokenRule(),
            new HardcodedCredentialRule(),
            new GitHubTokenRule(),
            new SlackTokenRule(),
            new StripeApiKeyRule(),
            new GoogleApiKeyRule(),
            new NpmTokenRule(),
            new WeakHashAlgorithmRule(),
            // Heuristic rules run last; pattern rules are higher-signal and cheaper.
            new ShannonEntropyRule(),
        };
    }

    public IEnumerable<IDetectionRule> GetRules() => _rules;
}
