using CodeSentinel.Infrastructure.Rules;

namespace CodeSentinel.Infrastructure.Tests.Rules;

public class GlobIgnorePolicyTests
{
    [Fact]
    public void ShouldIgnore_WithNoPatterns_AlwaysReturnsFalse()
    {
        var policy = new GlobIgnorePolicy([]);

        policy.ShouldIgnore("any/file.cs").Should().BeFalse();
        policy.ShouldIgnore("vendor/lib.js").Should().BeFalse();
    }

    [Theory]
    [InlineData("vendor/**",   "vendor/lib.js",      true)]
    [InlineData("vendor/**",   "vendor/sub/dep.js",  true)]
    [InlineData("vendor/**",   "src/main.cs",        false)]
    [InlineData("**/*.log",    "logs/error.log",     true)]
    [InlineData("**/*.log",    "src/main.cs",        false)]
    [InlineData("docs/**",     "docs/api.md",        true)]
    [InlineData("docs/**",     "src/docs.cs",        false)]
    [InlineData("*.min.js",    "bundle.min.js",      true)]
    [InlineData("*.min.js",    "src/bundle.min.js",  false)]
    public void ShouldIgnore_MatchesGlobPatterns(string pattern, string path, bool expected)
    {
        var policy = new GlobIgnorePolicy([pattern]);

        policy.ShouldIgnore(path).Should().Be(expected);
    }

    [Fact]
    public void ShouldIgnore_NormalizesWindowsBackslashes()
    {
        var policy = new GlobIgnorePolicy(["vendor/**"]);

        policy.ShouldIgnore(@"vendor\lib.js").Should().BeTrue();
        policy.ShouldIgnore(@"vendor\sub\nested.cs").Should().BeTrue();
    }

    [Fact]
    public void ShouldIgnore_AnyMatchingPatternTriggers()
    {
        var policy = new GlobIgnorePolicy(["docs/**", "*.log", "**/*.tmp"]);

        policy.ShouldIgnore("docs/api.md").Should().BeTrue();
        policy.ShouldIgnore("error.log").Should().BeTrue();
        policy.ShouldIgnore("build/cache.tmp").Should().BeTrue();
        policy.ShouldIgnore("src/main.cs").Should().BeFalse();
    }

    [Fact]
    public void ShouldIgnore_IsCaseInsensitive()
    {
        var policy = new GlobIgnorePolicy(["VENDOR/**"]);

        policy.ShouldIgnore("vendor/lib.js").Should().BeTrue();
        policy.ShouldIgnore("Vendor/Lib.JS").Should().BeTrue();
    }
}
