using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;
using CodeSentinel.Infrastructure.Rules.BuiltIn;

namespace CodeSentinel.Infrastructure.Tests.Rules;

public class AwsAccessKeyRuleTests
{
    private readonly AwsAccessKeyRule _rule = new();

    [Theory]
    [InlineData("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")]
    [InlineData("key = ASIAIOSFODNN7EXAMPLE")]  // ASIA prefix, exactly 16 trailing chars = valid format
    public async Task AnalyzeAsync_WithValidKey_ReturnsOneFinding(string line)
    {
        var file = MakeFile(line);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().HaveCount(1);
        findings[0].RuleId.Should().Be("CS001");
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public async Task AnalyzeAsync_SnippetDoesNotExposeRawKey()
    {
        var file = MakeFile("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings[0].Location.Snippet.Should().Contain("[REDACTED]");
        findings[0].Location.Snippet.Should().NotContain("AKIAIOSFODNN7EXAMPLE");
    }

    [Theory]
    [InlineData("AWS_REGION=us-east-1")]
    [InlineData("AKIA_NOT_A_KEY")]
    [InlineData("akiaiosfodnn7example")]  // must be uppercase
    public async Task AnalyzeAsync_WithNonMatchingLine_ReturnsEmpty(string line)
    {
        var file = MakeFile(line);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().BeEmpty();
    }

    private static ScannableFile MakeFile(params string[] lines) =>
        new("test.env", "test.env", lines);
}
