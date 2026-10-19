using CodeSentinel.Application.Security;

namespace CodeSentinel.Application.Tests.Security;

public class UrlRedactionTests
{
    [Theory]
    [InlineData("https://ghp_abc123@github.com/foo/bar.git", "https://***@github.com/foo/bar.git")]
    [InlineData("https://user:s3cret@example.com/repo.git", "https://***@example.com/repo.git")]
    [InlineData("https://user:p@ss@example.com/repo", "https://***@example.com/repo")]
    [InlineData("http://token@example.com", "http://***@example.com")]
    [InlineData("ssh://deploy:key@example.com:22/repo.git", "ssh://***@example.com:22/repo.git")]
    public void RedactUserInfo_MasksCredentials(string input, string expected)
    {
        UrlRedaction.RedactUserInfo(input).Should().Be(expected);
    }

    [Theory]
    [InlineData("https://github.com/foo/bar.git")]
    [InlineData("https://github.com/foo/bar@v1")]
    [InlineData("ssh://git@example.com/repo.git")]
    [InlineData("git@github.com:foo/bar.git")]
    [InlineData("/local/path")]
    [InlineData("")]
    public void RedactUserInfo_LeavesUrlsWithoutSecretsUnchanged(string input)
    {
        UrlRedaction.RedactUserInfo(input).Should().Be(input);
    }
}
