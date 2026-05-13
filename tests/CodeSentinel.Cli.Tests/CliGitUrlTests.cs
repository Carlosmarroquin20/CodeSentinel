using CodeSentinel.Cli;

namespace CodeSentinel.Cli.Tests;

public class CliGitUrlTests
{
    [Theory]
    [InlineData("https://github.com/foo/bar")]
    [InlineData("https://github.com/foo/bar.git")]
    [InlineData("HTTPS://EXAMPLE.com/repo.git")]
    [InlineData("http://example.com/repo.git")]
    [InlineData("git://example.com/repo.git")]
    [InlineData("ssh://git@example.com/repo.git")]
    [InlineData("git@github.com:foo/bar.git")]
    public void LooksLikeGitUrl_ReturnsTrueForGitUrls(string input)
    {
        CliApplication.LooksLikeGitUrl(input).Should().BeTrue();
    }

    [Theory]
    [InlineData("/local/path")]
    [InlineData("./relative")]
    [InlineData("../up")]
    [InlineData("C:\\Windows\\Path")]
    [InlineData("D:/Code/repo")]
    [InlineData("repo")]
    [InlineData("just-a-name")]
    public void LooksLikeGitUrl_ReturnsFalseForLocalPaths(string input)
    {
        CliApplication.LooksLikeGitUrl(input).Should().BeFalse();
    }
}
