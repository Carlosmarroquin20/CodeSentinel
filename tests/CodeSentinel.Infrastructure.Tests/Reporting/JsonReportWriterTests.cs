using System.Text.Json;
using CodeSentinel.Core.Findings;
using CodeSentinel.Core.Reporting;
using CodeSentinel.Core.Scanning;
using CodeSentinel.Core.Scoring;
using CodeSentinel.Infrastructure.Reporting.Json;

namespace CodeSentinel.Infrastructure.Tests.Reporting;

public class JsonReportWriterTests
{
    private readonly JsonReportWriter _writer = new();

    [Fact]
    public async Task WriteAsync_ProducesWellFormedJson()
    {
        using var stream = new MemoryStream();

        await _writer.WriteAsync(BuildReport(), stream, CancellationToken.None);

        stream.Position = 0;
        var act = () => JsonDocument.Parse(stream);
        act.Should().NotThrow();
    }

    [Fact]
    public async Task WriteAsync_ContainsExpectedTopLevelFields()
    {
        var root = await ParseRootAsync(BuildReport());

        root.GetProperty("scanner").GetString().Should().Be("CodeSentinel");
        root.GetProperty("version").GetString().Should().Be("0.1.0");
        root.GetProperty("target").GetString().Should().Be("/repo");
        root.TryGetProperty("scannedAt", out _).Should().BeTrue();
        root.TryGetProperty("summary", out _).Should().BeTrue();
        root.TryGetProperty("findings", out _).Should().BeTrue();
    }

    [Fact]
    public async Task WriteAsync_SummaryContainsScoreAndCounts()
    {
        var root = await ParseRootAsync(BuildReport());
        var summary = root.GetProperty("summary");

        summary.GetProperty("filesScanned").GetInt32().Should().Be(0);
        summary.GetProperty("findingCount").GetInt32().Should().Be(0);
        summary.GetProperty("duration").GetString().Should().NotBeNullOrEmpty();

        var score = summary.GetProperty("score");
        score.GetProperty("value").GetInt32().Should().Be(100);
        score.GetProperty("grade").GetString().Should().Be("A");
    }

    [Fact]
    public async Task WriteAsync_WithNoFindings_FindingsIsEmptyArray()
    {
        var root = await ParseRootAsync(BuildReport());

        root.GetProperty("findings").GetArrayLength().Should().Be(0);
    }

    [Fact]
    public async Task WriteAsync_WithFindings_SerializesAllFindingFields()
    {
        var report = BuildReportWithFindings(
            MakeFinding("CS001", "AWS Access Key ID", Severity.Critical, "src/config.env", 3));

        var root = await ParseRootAsync(report);
        var finding = root.GetProperty("findings")[0];

        finding.GetProperty("ruleId").GetString().Should().Be("CS001");
        finding.GetProperty("title").GetString().Should().Be("AWS Access Key ID");
        finding.GetProperty("severity").GetString().Should().Be("Critical");
        finding.GetProperty("confidence").GetDouble().Should().BeGreaterThan(0);

        var location = finding.GetProperty("location");
        location.GetProperty("file").GetString().Should().Be("src/config.env");
        location.GetProperty("line").GetInt32().Should().Be(3);
    }

    [Fact]
    public async Task WriteAsync_SortsFindingsBySeverityDescending()
    {
        var report = BuildReportWithFindings(
            MakeFinding("CS101", "Weak Hash", Severity.Medium, "a.cs", 1),
            MakeFinding("CS001", "AWS Key",   Severity.Critical, "b.cs", 1),
            MakeFinding("CS005", "Password",  Severity.High, "c.cs", 1));

        var root = await ParseRootAsync(report);
        var findings = root.GetProperty("findings");

        findings[0].GetProperty("ruleId").GetString().Should().Be("CS001");   // Critical
        findings[1].GetProperty("ruleId").GetString().Should().Be("CS005");   // High
        findings[2].GetProperty("ruleId").GetString().Should().Be("CS101");   // Medium
    }

    [Fact]
    public async Task WriteAsync_NullSnippet_OmittedFromJson()
    {
        var finding = new Finding(
            "CS003", "Private Key", "desc", Severity.Critical,
            new FileLocation("key.pem", 1, 1, Snippet: null),
            Confidence: 0.9);
        var report = BuildReportWithFindings(finding);

        var root = await ParseRootAsync(report);
        var location = root.GetProperty("findings")[0].GetProperty("location");

        location.TryGetProperty("snippet", out _).Should().BeFalse();
    }

    [Fact]
    public async Task WriteAsync_SummaryFindingCountMatchesFindingsArrayLength()
    {
        var report = BuildReportWithFindings(
            MakeFinding("CS001", "Key", Severity.Critical, "a.env", 1),
            MakeFinding("CS005", "Pwd", Severity.High, "b.py", 2));

        var root = await ParseRootAsync(report);

        var countInSummary = root.GetProperty("summary").GetProperty("findingCount").GetInt32();
        var countInArray   = root.GetProperty("findings").GetArrayLength();

        countInSummary.Should().Be(countInArray);
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

    private static ScanReport BuildReport() =>
        new("/repo", DateTimeOffset.UtcNow, "0.1.0", ScanResult.Empty(SecurityScore.Perfect));

    private static ScanReport BuildReportWithFindings(params Finding[] findings)
    {
        var score = new SecurityScore(70, "C");
        var result = new ScanResult(findings, FilesScanned: 1, Duration: TimeSpan.FromMilliseconds(50), score);
        return new ScanReport("/repo", DateTimeOffset.UtcNow, "0.1.0", result);
    }

    private static Finding MakeFinding(string ruleId, string title, Severity severity, string file, int line) =>
        new(ruleId, title, "description", severity,
            new FileLocation(file, line, ColumnNumber: 1, Snippet: $"{title} at line {line}"),
            Confidence: 0.9);
}
