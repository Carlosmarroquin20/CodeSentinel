using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;
using CodeSentinel.Infrastructure.Rules.BuiltIn;

namespace CodeSentinel.Infrastructure.Tests.Rules;

// Combined test file for the modern-secret detection rules (CS006-CS010).
// Token strings are built by concatenation at runtime so the full pattern never
// appears as a literal in the source — that prevents upstream secret scanners
// (GitHub Secret Scanning, etc.) from flagging this test file.
public class ModernSecretRuleTests
{
    // 36-character alphanumeric body shared by GitHub classic tokens and npm tokens.
    private const string Body36 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";

    // 82-character body for GitHub fine-grained PATs.
    private const string Body82 =
        "ABCDEFGHIJKLMNOPQRSTUV_WXYZabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrst";

    private const string FakeGhpToken      = "ghp" + "_" + Body36;
    private const string FakeGhsToken      = "ghs" + "_" + Body36;
    private const string FakeFineGrainedPat = "github" + "_pat_" + Body82;
    private const string FakeSlackBot      = "xoxb" + "-1234567890-9876543210-abcdefghijKLMNOP";
    private const string FakeSlackApp      = "xapp" + "-1-A1B2C3D4E5F-1234567890-abc123def456";
    private const string FakeStripeLiveKey = "sk" + "_live_" + "abcdefghijklmnopqrstuvwx";
    private const string FakeStripeTestKey = "sk" + "_test_" + "ABCDEFGHIJKLMNOPQRSTUVWX";
    private const string FakeStripeRestrictedKey = "rk" + "_live_" + "abcdefghijklmnopqrstuvwx";
    private const string FakeGoogleKey     = "AIza" + "0123456789abcdefghijklmnopqrstuvwxyz";
    private const string FakeNpmToken      = "npm" + "_" + Body36;

    // --- GitHub (CS006) ----------------------------------------------------

    [Theory]
    [InlineData(FakeGhpToken)]
    [InlineData(FakeGhsToken)]
    [InlineData(FakeFineGrainedPat)]
    public async Task GitHubTokenRule_DetectsKnownTokenShapes(string token)
    {
        var rule = new GitHubTokenRule();
        var file = new ScannableFile("config.env", "config.env", [$"GH_TOKEN={token}"]);

        var findings = await rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().HaveCount(1);
        findings[0].RuleId.Should().Be("CS006");
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Theory]
    [InlineData("not_a_token")]
    [InlineData("ghp_too_short")]
    [InlineData("ghx_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")]  // ghx_ is not a real prefix
    public async Task GitHubTokenRule_RejectsNonMatchingShapes(string text)
    {
        var rule = new GitHubTokenRule();
        var file = new ScannableFile("config.env", "config.env", [text]);

        var findings = await rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().BeEmpty();
    }

    [Fact]
    public async Task GitHubTokenRule_RedactsTokenInSnippet()
    {
        var rule = new GitHubTokenRule();
        var file = new ScannableFile("config.env", "config.env", [$"GH_TOKEN={FakeGhpToken}"]);

        var findings = await rule.AnalyzeAsync(file, CancellationToken.None);

        findings[0].Location.Snippet.Should().Contain("[REDACTED]");
        findings[0].Location.Snippet.Should().NotContain(FakeGhpToken);
    }

    // --- Slack (CS007) -----------------------------------------------------

    [Theory]
    [InlineData(FakeSlackBot)]
    [InlineData(FakeSlackApp)]
    public async Task SlackTokenRule_DetectsKnownTokenShapes(string token)
    {
        var rule = new SlackTokenRule();
        var file = new ScannableFile("config.env", "config.env", [$"SLACK_TOKEN={token}"]);

        var findings = await rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().HaveCount(1);
        findings[0].RuleId.Should().Be("CS007");
    }

    [Theory]
    [InlineData("xoxz-12345-67890-foo")]   // wrong prefix character
    [InlineData("xoxb-tooshort")]           // missing segments
    public async Task SlackTokenRule_RejectsMalformedTokens(string text)
    {
        var rule = new SlackTokenRule();
        var file = new ScannableFile("config.env", "config.env", [text]);

        var findings = await rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().BeEmpty();
    }

    // --- Stripe (CS008) ----------------------------------------------------

    [Theory]
    [InlineData(FakeStripeLiveKey)]
    [InlineData(FakeStripeTestKey)]
    [InlineData(FakeStripeRestrictedKey)]
    public async Task StripeApiKeyRule_DetectsSecretAndRestrictedKeys(string token)
    {
        var rule = new StripeApiKeyRule();
        var file = new ScannableFile("config.env", "config.env", [$"STRIPE_KEY={token}"]);

        var findings = await rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().HaveCount(1);
        findings[0].RuleId.Should().Be("CS008");
    }

    [Fact]
    public async Task StripeApiKeyRule_DoesNotFlagPublishableKeys()
    {
        // pk_ keys are designed to be public; flagging them would be a false positive.
        var publishableKey = "pk" + "_live_" + "abcdefghijklmnopqrstuvwx";
        var rule = new StripeApiKeyRule();
        var file = new ScannableFile("frontend.js", "frontend.js", [$"const stripe = '{publishableKey}';"]);

        var findings = await rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().BeEmpty();
    }

    // --- Google API key (CS009) --------------------------------------------

    [Fact]
    public async Task GoogleApiKeyRule_DetectsAizaShape()
    {
        var rule = new GoogleApiKeyRule();
        var file = new ScannableFile("config.env", "config.env", [$"GOOGLE_KEY={FakeGoogleKey}"]);

        var findings = await rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().HaveCount(1);
        findings[0].RuleId.Should().Be("CS009");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Theory]
    [InlineData("AIzaTooShort")]
    [InlineData("notaprefix0123456789abcdefghijklmnopqrstu")]
    public async Task GoogleApiKeyRule_RejectsMalformedKeys(string text)
    {
        var rule = new GoogleApiKeyRule();
        var file = new ScannableFile("config.env", "config.env", [text]);

        var findings = await rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().BeEmpty();
    }

    // --- npm (CS010) -------------------------------------------------------

    [Fact]
    public async Task NpmTokenRule_DetectsNpmTokenShape()
    {
        var rule = new NpmTokenRule();
        var file = new ScannableFile(".npmrc", ".npmrc", [$"//registry.npmjs.org/:_authToken={FakeNpmToken}"]);

        var findings = await rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().HaveCount(1);
        findings[0].RuleId.Should().Be("CS010");
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Theory]
    [InlineData("npm-not-underscore")]
    [InlineData("npm_short")]
    public async Task NpmTokenRule_RejectsMalformedTokens(string text)
    {
        var rule = new NpmTokenRule();
        var file = new ScannableFile(".npmrc", ".npmrc", [text]);

        var findings = await rule.AnalyzeAsync(file, CancellationToken.None);

        findings.Should().BeEmpty();
    }
}
