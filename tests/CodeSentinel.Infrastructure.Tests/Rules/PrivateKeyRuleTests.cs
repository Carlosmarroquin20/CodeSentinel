using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;
using CodeSentinel.Infrastructure.Rules.BuiltIn;

namespace CodeSentinel.Infrastructure.Tests.Rules;

public class PrivateKeyRuleTests
{
    private readonly PrivateKeyRule _rule = new();

    [Theory]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----")]
    [InlineData("-----BEGIN EC PRIVATE KEY-----")]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----")]
    [InlineData("-----BEGIN PRIVATE KEY-----")]
    [InlineData("-----BEGIN PGP PRIVATE KEY-----")]
    [InlineData("-----BEGIN PGP PRIVATE KEY BLOCK-----")]
    [InlineData("-----BEGIN DSA PRIVATE KEY-----")]
    [InlineData("-----BEGIN ENCRYPTED PRIVATE KEY-----")]
    public async Task AnalyzeAsync_WithKnownPemHeader_ReturnsOneFinding(string header)
    {
        var file = new ScannableFile("id_rsa", "id_rsa", [header]);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].RuleId.Should().Be("CS003");
    }

    [Theory]
    [InlineData("-----BEGIN PUBLIC KEY-----")]
    [InlineData("-----BEGIN PGP PUBLIC KEY BLOCK-----")]
    [InlineData("-----BEGIN CERTIFICATE-----")]
    public async Task AnalyzeAsync_WithPublicMaterialHeader_ReturnsEmpty(string header)
    {
        var file = new ScannableFile("id_rsa.pub", "id_rsa.pub", [header]);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().BeEmpty();
    }
}
