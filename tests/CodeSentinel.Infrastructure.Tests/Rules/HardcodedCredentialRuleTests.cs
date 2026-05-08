using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;
using CodeSentinel.Infrastructure.Rules.BuiltIn;

namespace CodeSentinel.Infrastructure.Tests.Rules;

public class HardcodedCredentialRuleTests
{
    private readonly HardcodedCredentialRule _rule = new();

    [Theory]
    [InlineData(@"password = ""MySecretPassword123""")]
    [InlineData(@"api_key = ""abcdefghijklmnop""")]
    [InlineData(@"secret: 'mysupersecrettoken'")]
    [InlineData(@"client_secret=""my-oauth-client-secret""")]
    public async Task AnalyzeAsync_WithHardcodedCredential_ReturnsOneFinding(string line)
    {
        var file = new ScannableFile("config.yaml", "config.yaml", [line]);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().HaveCount(1);
        findings[0].RuleId.Should().Be("CS005");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public async Task AnalyzeAsync_SnippetPreservesKeyNameAndRedactsValue()
    {
        var file = new ScannableFile("config.yaml", "config.yaml", [@"password = ""MySecretPassword123"""]);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings[0].Location.Snippet.Should().Contain("password");
        findings[0].Location.Snippet.Should().Contain("[REDACTED]");
        findings[0].Location.Snippet.Should().NotContain("MySecretPassword123");
    }

    [Theory]
    [InlineData(@"password = ""short""")]    // under 8 chars
    [InlineData("# password: see vault")]    // comment, no value
    public async Task AnalyzeAsync_WithNonMatchingLine_ReturnsEmpty(string line)
    {
        var file = new ScannableFile("config.yaml", "config.yaml", [line]);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().BeEmpty();
    }
}
