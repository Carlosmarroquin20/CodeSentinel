using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;
using CodeSentinel.Infrastructure.Rules.BuiltIn;

namespace CodeSentinel.Infrastructure.Tests.Rules;

public class WeakHashAlgorithmRuleTests
{
    private readonly WeakHashAlgorithmRule _rule = new();

    [Theory]
    [InlineData("var h = MD5.Create();")]
    [InlineData("var h = SHA1.Create();")]
    [InlineData("new MD5CryptoServiceProvider()")]
    [InlineData("hashlib.md5(data)")]
    [InlineData("hashlib.sha1(data)")]
    [InlineData(@"MessageDigest.getInstance(""MD5"")")]
    [InlineData(@"MessageDigest.getInstance(""SHA-1"")")]
    public async Task AnalyzeAsync_WithWeakHashUsage_ReturnsOneFinding(string line)
    {
        var file = new ScannableFile("crypto.cs", "crypto.cs", [line]);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().HaveCount(1);
        findings[0].RuleId.Should().Be("CS101");
        findings[0].Severity.Should().Be(Severity.Medium);
    }

    [Theory]
    [InlineData("var h = SHA256.Create();")]
    [InlineData("var h = SHA512.Create();")]
    [InlineData("hashlib.sha256(data)")]
    public async Task AnalyzeAsync_WithStrongHashUsage_ReturnsEmpty(string line)
    {
        var file = new ScannableFile("crypto.cs", "crypto.cs", [line]);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().BeEmpty();
    }
}
