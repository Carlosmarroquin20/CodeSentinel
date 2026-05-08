using CodeSentinel.Core.Detection;
using CodeSentinel.Infrastructure.Rules.Heuristics;

namespace CodeSentinel.Infrastructure.Tests.Rules;

public class ShannonEntropyRuleTests
{
    private readonly ShannonEntropyRule _rule = new();

    [Fact]
    public async Task AnalyzeAsync_WithHighEntropyQuotedString_ReturnsFinding()
    {
        // Random-looking alphanumeric content characteristic of real API keys or secrets.
        var line = @"secret = ""wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY""";
        var file = new ScannableFile("config.env", "config.env", [line]);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().HaveCount(1);
        findings[0].RuleId.Should().Be("CS900");
    }

    [Theory]
    [InlineData(@"msg = ""aaaaaaaaaaaaaaaaaaaaaaaaaa""")]          // repetitive, low entropy
    [InlineData(@"url = ""https://example.com/some/path""")]       // prose, low entropy
    [InlineData(@"key = ""short""")]                               // too short
    public async Task AnalyzeAsync_WithLowEntropyOrShortString_ReturnsEmpty(string line)
    {
        var file = new ScannableFile("config.env", "config.env", [line]);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task AnalyzeAsync_SnippetDoesNotExposeRawValue()
    {
        var secretValue = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        var line = $@"secret = ""{secretValue}""";
        var file = new ScannableFile("config.env", "config.env", [line]);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings[0].Location.Snippet.Should().Contain("[REDACTED]");
        findings[0].Location.Snippet.Should().NotContain(secretValue);
    }
}
