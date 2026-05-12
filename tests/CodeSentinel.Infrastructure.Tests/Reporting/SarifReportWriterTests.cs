using System.Text.Json;
using CodeSentinel.Application.Abstractions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;
using CodeSentinel.Core.Reporting;
using CodeSentinel.Core.Scanning;
using CodeSentinel.Core.Scoring;
using CodeSentinel.Infrastructure.Reporting.Sarif;

namespace CodeSentinel.Infrastructure.Tests.Reporting;

public class SarifReportWriterTests
{
    private readonly SarifReportWriter _writer;

    public SarifReportWriterTests()
    {
        _writer = new SarifReportWriter(new TestRuleProvider());
    }

    [Fact]
    public void Format_IsSarif()
    {
        _writer.Format.Should().Be("sarif");
    }

    [Fact]
    public async Task WriteAsync_ProducesValidJson()
    {
        using var stream = new MemoryStream();

        await _writer.WriteAsync(BuildEmptyReport(), stream, CancellationToken.None);

        stream.Position = 0;
        var act = () => JsonDocument.Parse(stream);
        act.Should().NotThrow();
    }

    [Fact]
    public async Task WriteAsync_IncludesSarifSchemaAndVersion()
    {
        var root = await ParseRootAsync(BuildEmptyReport());

        root.GetProperty("$schema").GetString().Should().Contain("sarif-schema-2.1.0.json");
        root.GetProperty("version").GetString().Should().Be("2.1.0");
    }

    [Fact]
    public async Task WriteAsync_IncludesSingleRunWithToolDriver()
    {
        var root = await ParseRootAsync(BuildEmptyReport());

        var runs = root.GetProperty("runs");
        runs.GetArrayLength().Should().Be(1);

        var driver = runs[0].GetProperty("tool").GetProperty("driver");
        driver.GetProperty("name").GetString().Should().Be("CodeSentinel");
        driver.GetProperty("version").GetString().Should().Be("0.1.0");
        driver.TryGetProperty("informationUri", out _).Should().BeTrue();
    }

    [Fact]
    public async Task WriteAsync_ToolDriverIncludesAllRegisteredRules()
    {
        // Even when no finding fires, the tool advertises every rule it can detect.
        var root = await ParseRootAsync(BuildEmptyReport());

        var rules = root.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver").GetProperty("rules");

        rules.GetArrayLength().Should().Be(2); // TestRuleProvider returns 2 rules
        rules[0].GetProperty("id").GetString().Should().Be("TEST001");
        rules[0].GetProperty("defaultConfiguration").GetProperty("level").GetString().Should().Be("error");
        rules[1].GetProperty("id").GetString().Should().Be("TEST002");
        rules[1].GetProperty("defaultConfiguration").GetProperty("level").GetString().Should().Be("warning");
    }

    [Fact]
    public async Task WriteAsync_WithNoFindings_ResultsIsEmptyArray()
    {
        var root = await ParseRootAsync(BuildEmptyReport());

        var results = root.GetProperty("runs")[0].GetProperty("results");
        results.GetArrayLength().Should().Be(0);
    }

    [Fact]
    public async Task WriteAsync_WithFindings_SerializesResultsArray()
    {
        var finding = new Finding(
            RuleId: "TEST001",
            Title: "Test Critical",
            Description: "desc",
            Severity: Severity.Critical,
            Location: new FileLocation("src/app.cs", LineNumber: 10, ColumnNumber: 3, Snippet: "secret = [REDACTED]"),
            Confidence: 0.9);

        var report = BuildReportWithFindings(finding);
        var root = await ParseRootAsync(report);
        var result = root.GetProperty("runs")[0].GetProperty("results")[0];

        result.GetProperty("ruleId").GetString().Should().Be("TEST001");
        result.GetProperty("level").GetString().Should().Be("error");
        result.GetProperty("message").GetProperty("text").GetString().Should().Be("Test Critical");
    }

    [Fact]
    public async Task WriteAsync_PhysicalLocationCarriesUriAndRegion()
    {
        var finding = new Finding(
            "TEST001", "T", "d", Severity.Critical,
            new FileLocation("src/dir/app.cs", LineNumber: 42, ColumnNumber: 5, Snippet: "leak"),
            Confidence: 0.9);

        var root = await ParseRootAsync(BuildReportWithFindings(finding));
        var location = root.GetProperty("runs")[0].GetProperty("results")[0]
            .GetProperty("locations")[0].GetProperty("physicalLocation");

        location.GetProperty("artifactLocation").GetProperty("uri").GetString()
            .Should().Be("src/dir/app.cs");

        var region = location.GetProperty("region");
        region.GetProperty("startLine").GetInt32().Should().Be(42);
        region.GetProperty("startColumn").GetInt32().Should().Be(5);
        region.GetProperty("snippet").GetProperty("text").GetString().Should().Be("leak");
    }

    [Fact]
    public async Task WriteAsync_NormalizesWindowsPathSeparators()
    {
        // SARIF artifact URIs must use forward slashes regardless of host OS.
        var finding = new Finding(
            "TEST001", "T", "d", Severity.Critical,
            new FileLocation(@"src\dir\app.cs", LineNumber: 1, ColumnNumber: 1, Snippet: null),
            Confidence: 0.9);

        var root = await ParseRootAsync(BuildReportWithFindings(finding));

        var uri = root.GetProperty("runs")[0].GetProperty("results")[0]
            .GetProperty("locations")[0]
            .GetProperty("physicalLocation").GetProperty("artifactLocation")
            .GetProperty("uri").GetString();

        uri.Should().Be("src/dir/app.cs");
        uri.Should().NotContain(@"\");
    }

    [Theory]
    [InlineData(Severity.Critical, "error")]
    [InlineData(Severity.High,     "error")]
    [InlineData(Severity.Medium,   "warning")]
    [InlineData(Severity.Low,      "note")]
    [InlineData(Severity.Info,     "none")]
    public async Task WriteAsync_MapsSeverityToSarifLevel(Severity severity, string expectedLevel)
    {
        var finding = new Finding(
            "TEST001", "T", "d", severity,
            new FileLocation("a.cs", 1, 1, Snippet: null),
            Confidence: 0.9);

        var root = await ParseRootAsync(BuildReportWithFindings(finding));

        root.GetProperty("runs")[0].GetProperty("results")[0]
            .GetProperty("level").GetString().Should().Be(expectedLevel);
    }

    [Fact]
    public async Task WriteAsync_NullSnippet_OmitsSnippetProperty()
    {
        var finding = new Finding(
            "TEST001", "T", "d", Severity.Critical,
            new FileLocation("a.cs", 1, 1, Snippet: null),
            Confidence: 0.9);

        var root = await ParseRootAsync(BuildReportWithFindings(finding));
        var region = root.GetProperty("runs")[0].GetProperty("results")[0]
            .GetProperty("locations")[0]
            .GetProperty("physicalLocation").GetProperty("region");

        region.TryGetProperty("snippet", out _).Should().BeFalse();
    }

    [Fact]
    public async Task WriteAsync_SortsResultsBySeverityDescending()
    {
        var lowFinding    = new Finding("TEST002", "Low",    "d", Severity.Low,      new FileLocation("a.cs", 1, 1, null), 0.9);
        var critFinding   = new Finding("TEST001", "Crit",   "d", Severity.Critical, new FileLocation("b.cs", 1, 1, null), 0.9);
        var mediumFinding = new Finding("TEST002", "Medium", "d", Severity.Medium,   new FileLocation("c.cs", 1, 1, null), 0.9);

        var root = await ParseRootAsync(BuildReportWithFindings(lowFinding, critFinding, mediumFinding));
        var results = root.GetProperty("runs")[0].GetProperty("results");

        results[0].GetProperty("message").GetProperty("text").GetString().Should().Be("Crit");
        results[1].GetProperty("message").GetProperty("text").GetString().Should().Be("Medium");
        results[2].GetProperty("message").GetProperty("text").GetString().Should().Be("Low");
    }

    // --- helpers ---

    private async Task<JsonElement> ParseRootAsync(ScanReport report)
    {
        using var stream = new MemoryStream();
        await _writer.WriteAsync(report, stream, CancellationToken.None);
        stream.Position = 0;
        var doc = await JsonDocument.ParseAsync(stream);
        return doc.RootElement.Clone();
    }

    private static ScanReport BuildEmptyReport() =>
        new("/repo", DateTimeOffset.UtcNow, "0.1.0", ScanResult.Empty(SecurityScore.Perfect));

    private static ScanReport BuildReportWithFindings(params Finding[] findings)
    {
        var result = new ScanResult(findings, FilesScanned: 1, Duration: TimeSpan.FromMilliseconds(10), new SecurityScore(50, "D"));
        return new ScanReport("/repo", DateTimeOffset.UtcNow, "0.1.0", result);
    }

    // Test-only rule provider with a stable two-rule set so the tool descriptor is predictable.
    private sealed class TestRuleProvider : IRuleProvider
    {
        public IEnumerable<IDetectionRule> GetRules() =>
        [
            new FakeRule(new RuleMetadata("TEST001", "Test Critical", "First test rule",
                RuleCategory.Secret, Severity.Critical)),
            new FakeRule(new RuleMetadata("TEST002", "Test Medium", "Second test rule",
                RuleCategory.InsecurePattern, Severity.Medium)),
        ];

        private sealed class FakeRule : IDetectionRule
        {
            public FakeRule(RuleMetadata metadata) => Metadata = metadata;
            public RuleMetadata Metadata { get; }
            public ValueTask<IReadOnlyList<Finding>> AnalyzeAsync(ScannableFile file, CancellationToken cancellationToken) =>
                ValueTask.FromResult<IReadOnlyList<Finding>>([]);
        }
    }
}
