using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;
using CodeSentinel.Infrastructure.Rules.BuiltIn;

namespace CodeSentinel.Infrastructure.Tests.Rules;

public class AwsAccessKeyRuleTests
{
    // Concatenated at runtime so the full pattern does not appear as a literal string,
    // which would trigger secret scanners on repositories that host this scanner's own tests.
    private const string FakeLongTermKeyId  = "AKIA" + "IOSFODNN7EXAMPLE";
    private const string FakeTemporaryKeyId = "ASIA" + "IOSFODNN7EXAMPLE";

    private readonly AwsAccessKeyRule _rule = new();

    [Theory]
    [InlineData("AWS_ACCESS_KEY_ID=", FakeLongTermKeyId)]
    [InlineData("key = ",             FakeTemporaryKeyId)]
    public async Task AnalyzeAsync_WithValidKey_ReturnsOneFinding(string prefix, string key)
    {
        var file = MakeFile(prefix + key);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().HaveCount(1);
        findings[0].RuleId.Should().Be("CS001");
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public async Task AnalyzeAsync_SnippetDoesNotExposeRawKey()
    {
        var file = MakeFile("AWS_ACCESS_KEY_ID=" + FakeLongTermKeyId);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings[0].Location.Snippet.Should().Contain("[REDACTED]");
        findings[0].Location.Snippet.Should().NotContain(FakeLongTermKeyId);
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
