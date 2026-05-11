using CodeSentinel.Application.Abstractions;
using Microsoft.Extensions.FileSystemGlobbing;

namespace CodeSentinel.Infrastructure.Rules;

internal sealed class GlobIgnorePolicy : IIgnorePolicy
{
    private readonly Matcher? _matcher;

    public GlobIgnorePolicy(IReadOnlyCollection<string> globs)
    {
        ArgumentNullException.ThrowIfNull(globs);

        if (globs.Count == 0)
            return;

        _matcher = new Matcher(StringComparison.OrdinalIgnoreCase);
        foreach (var glob in globs)
        {
            _matcher.AddInclude(glob);
        }
    }

    public bool ShouldIgnore(string relativePath)
    {
        if (_matcher is null)
            return false;

        // Glob matchers expect forward slashes; native paths on Windows use backslashes.
        var normalized = relativePath.Replace('\\', '/');
        return _matcher.Match(normalized).HasMatches;
    }
}
