using CodeSentinel.Core.Detection;

namespace CodeSentinel.Application.Abstractions;

public interface IRuleProvider
{
    IEnumerable<IDetectionRule> GetRules();
}
