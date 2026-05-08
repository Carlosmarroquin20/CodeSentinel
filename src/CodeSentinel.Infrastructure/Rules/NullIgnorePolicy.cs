using CodeSentinel.Application.Abstractions;

namespace CodeSentinel.Infrastructure.Rules;

// Accepts all paths. Replaced in a future phase when .codesentinelignore file support is added.
internal sealed class NullIgnorePolicy : IIgnorePolicy
{
    public bool ShouldIgnore(string relativePath) => false;
}
