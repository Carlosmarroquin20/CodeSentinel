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
    [InlineData(@"<s:Boolean x:Key=""/Default/CodeEditing/Intellisense/LookupWindow/ShowSummary/@EntryValue"">True</s:Boolean>")]
    [InlineData(@"<Pack Condition=""$([MSBuild]::IsTargetFrameworkCompatible('$(TargetFramework)', 'net7.0'))"">")]
    [InlineData(@"var r = new Regex(""^(?<shortTypeName>[^:]+)::(?<memberName>[A-Za-z][A-Za-z0-9]*)$"");")]
    [InlineData(@"/// <see cref=""M:Serilog.Core.Logger.Write(Serilog.Events.LogEventLevel,System.Exception)""/>")]
    [InlineData(@"import Panel from ""src/components/UserProfileSettingsPanel""")]
    public async Task AnalyzeAsync_WithLowEntropyShortOrStructuredString_ReturnsEmpty(string line)
    {
        var file = new ScannableFile("config.env", "config.env", [line]);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().BeEmpty();
    }

    [Theory]
    [InlineData("Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZmdoaWprbA==")]       // base64
    [InlineData("q8Xr_2Lp-Vt9Kw4Zb7Nm1Yc5Hd3Jf6Gs")]                 // base64url
    public async Task AnalyzeAsync_WithSecretAlphabets_ReturnsFinding(string value)
    {
        var file = new ScannableFile("config.env", "config.env", [$"token: \"{value}\""]);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().ContainSingle().Which.RuleId.Should().Be("CS900");
    }

    [Fact]
    public async Task AnalyzeAsync_WithHexDigest_ReturnsEmpty()
    {
        // Hex has at most 4 bits of entropy per character, below the 4.5 threshold, so
        // commit SHAs and integrity hashes are never reported. This is deliberate.
        var file = new ScannableFile("deps.lock", "deps.lock", ["commit: \"e83c5163316f89bfbde7d9ab23ca2e25604af290\""]);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().BeEmpty();
    }

    [Theory]
    [InlineData(@"      ""integrity"": ""sha512-UqC2k6S6B7UrabdInpR1vP43TNaUI/udqV8z2M7gF1qu+hNXSTZoK+g5W2KCxf8q/BuCA59878nesxiMVP434w=="",")]
    [InlineData(@"      ""integrity"": ""sha1-rMZwR7Ls8k69fMHfbsgeduXcX1M="",")]
    [InlineData(@"<script src=""app.js"" integrity=""sha384-l7aqr++kIPTmX+hmXLQuvZF4aJ4ZGDg9DSRCzpSjrOEqQhScRuxoNQNSnzrFdwjq""></script>")]
    [InlineData(@"<link href=""app.css"" integrity=""sha256-o37YhoI/xaFj8VePdooLXJEpYeYAsmj7Uip3yHz4D/I="">")]
    public async Task AnalyzeAsync_WithIntegrityDigest_ReturnsEmpty(string line)
    {
        // npm lockfiles carry one of these per package; a single project produced thousands of findings.
        var file = new ScannableFile("package-lock.json", "package-lock.json", [line]);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task AnalyzeAsync_WithDigestPrefixButWrongLength_ReturnsFinding()
    {
        // Only the exact digest length is exempt, so a prefix alone does not hide a secret.
        var file = new ScannableFile("config.env", "config.env", [@"token: ""sha512-q8Xr2Lp9Vt9Kw4Zb7Nm1Yc5Hd3Jf6GsT0aB"""]);

        var findings = await _rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().ContainSingle().Which.RuleId.Should().Be("CS900");
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
