using System.Text;
using CodeSentinel.Core.Findings;
using CodeSentinel.Core.Reporting;
using CodeSentinel.Core.Scanning;
using CodeSentinel.Core.Scoring;
using CodeSentinel.Infrastructure.Reporting.Html;

namespace CodeSentinel.Infrastructure.Tests.Reporting;

public class HtmlReportWriterTests
{
    private readonly HtmlReportWriter _writer = new();

    [Fact]
    public void Format_IsHtml()
    {
        _writer.Format.Should().Be("html");
    }

    [Fact]
    public async Task WriteAsync_ProducesValidHtmlStructure()
    {
        var html = await RenderAsync(BuildEmptyReport());

        html.Should().StartWith("<!DOCTYPE html>");
        html.Should().Contain("<html lang=\"en\">");
        html.Should().Contain("<head>");
        html.Should().Contain("<body>");
        html.Should().EndWith("</body></html>");
    }

    [Fact]
    public async Task WriteAsync_EmbedsCss()
    {
        var html = await RenderAsync(BuildEmptyReport());

        html.Should().Contain("<style>");
        html.Should().Contain(".badge-critical");
        html.Should().Contain(".score-A");
    }

    [Fact]
    public async Task WriteAsync_RendersHeaderWithMetadata()
    {
        var report = new ScanReport(
            "/repo/myproject",
            new DateTimeOffset(2026, 5, 7, 14, 30, 0, TimeSpan.Zero),
            "0.1.0",
            ScanResult.Empty(SecurityScore.Perfect));

        var html = await RenderAsync(report);

        html.Should().Contain("CodeSentinel Security Report");
        html.Should().Contain("/repo/myproject");
        html.Should().Contain("0.1.0");
        html.Should().Contain("2026-05-07");
    }

    [Fact]
    public async Task WriteAsync_RendersScoreWithGradeClass()
    {
        var report = BuildReportWithScore(new SecurityScore(72, "C"));

        var html = await RenderAsync(report);

        html.Should().Contain("score-C");
        html.Should().Contain(">72<");
        html.Should().Contain("Grade C");
    }

    [Fact]
    public async Task WriteAsync_WithNoFindings_DisplaysEmptyStateMessage()
    {
        var html = await RenderAsync(BuildEmptyReport());

        html.Should().Contain("No security issues detected");
        html.Should().NotContain("<table>");
    }

    [Fact]
    public async Task WriteAsync_WithFindings_RendersFindingsTable()
    {
        var report = BuildReportWithFindings(
            MakeFinding("CS001", "AWS Access Key", Severity.Critical, "src/config.env", 5));

        var html = await RenderAsync(report);

        html.Should().Contain("<table>");
        html.Should().Contain("CS001");
        html.Should().Contain("AWS Access Key");
        html.Should().Contain("src/config.env:5");
        html.Should().Contain("badge-critical");
    }

    [Fact]
    public async Task WriteAsync_RendersBadgeClassPerSeverity()
    {
        var report = BuildReportWithFindings(
            MakeFinding("R1", "T1", Severity.Critical, "a", 1),
            MakeFinding("R2", "T2", Severity.High,     "b", 1),
            MakeFinding("R3", "T3", Severity.Medium,   "c", 1),
            MakeFinding("R4", "T4", Severity.Low,      "d", 1),
            MakeFinding("R5", "T5", Severity.Info,     "e", 1));

        var html = await RenderAsync(report);

        html.Should().Contain("badge-critical");
        html.Should().Contain("badge-high");
        html.Should().Contain("badge-medium");
        html.Should().Contain("badge-low");
        html.Should().Contain("badge-info");
    }

    [Fact]
    public async Task WriteAsync_SortsFindingsBySeverityDescending()
    {
        var report = BuildReportWithFindings(
            MakeFinding("LOW",  "low-rule",      Severity.Low,      "x.cs", 1),
            MakeFinding("CRIT", "critical-rule", Severity.Critical, "x.cs", 2),
            MakeFinding("MED",  "medium-rule",   Severity.Medium,   "x.cs", 3));

        var html = await RenderAsync(report);

        var critIndex = html.IndexOf("critical-rule", StringComparison.Ordinal);
        var medIndex  = html.IndexOf("medium-rule",   StringComparison.Ordinal);
        var lowIndex  = html.IndexOf("low-rule",      StringComparison.Ordinal);

        critIndex.Should().BeLessThan(medIndex);
        medIndex.Should().BeLessThan(lowIndex);
    }

    [Fact]
    public async Task WriteAsync_HtmlEscapesUnsafeFindingContent()
    {
        // A real scanned file could contain HTML/JS in its source. The report MUST escape
        // it so the HTML is safe to open in a browser even when findings come from
        // an attacker-controlled repository.
        var maliciousFinding = new Finding(
            RuleId: "CS001",
            Title: "Title with <b>HTML</b>",
            Description: "desc",
            Severity: Severity.Critical,
            Location: new FileLocation(
                FilePath: "evil<script>alert('xss')</script>.cs",
                LineNumber: 1,
                ColumnNumber: 1,
                Snippet: "var x = \"<img src=x onerror=alert(1)>\";"),
            Confidence: 0.9);

        var report = BuildReportWithFindings(maliciousFinding);
        var html = await RenderAsync(report);

        // The dangerous tag openings must not appear unescaped — that is what
        // makes the payloads inert when the browser parses the document.
        html.Should().NotContain("<script>alert");
        html.Should().NotContain("<img src=x");
        html.Should().NotContain("<b>HTML</b>");

        html.Should().Contain("&lt;script&gt;");
        html.Should().Contain("&lt;b&gt;HTML&lt;/b&gt;");
        html.Should().Contain("&lt;img src=x onerror=alert(1)&gt;");
    }

    [Fact]
    public async Task WriteAsync_HtmlEscapesTargetPath()
    {
        var report = new ScanReport(
            "/repo/<script>alert(1)</script>",
            DateTimeOffset.UtcNow,
            "0.1.0",
            ScanResult.Empty(SecurityScore.Perfect));

        var html = await RenderAsync(report);

        html.Should().NotContain("<script>alert(1)</script>");
        html.Should().Contain("&lt;script&gt;alert(1)&lt;/script&gt;");
    }

    [Fact]
    public async Task WriteAsync_NullSnippet_ProducesEmptyCellWithoutPreTag()
    {
        var finding = new Finding(
            "CS003", "Private Key", "desc", Severity.Critical,
            new FileLocation("key.pem", 1, 1, Snippet: null),
            Confidence: 0.9);
        var report = BuildReportWithFindings(finding);

        var html = await RenderAsync(report);

        // The row exists for the finding, but no <pre class="snippet"> wraps a null value.
        html.Should().Contain("Private Key");
        var preCount = CountOccurrences(html, "<pre class=\"snippet\">");
        preCount.Should().Be(0);
    }

    [Fact]
    public async Task WriteAsync_OutputIsUtf8WithoutBom()
    {
        using var stream = new MemoryStream();
        await _writer.WriteAsync(BuildEmptyReport(), stream, CancellationToken.None);

        var bytes = stream.ToArray();
        bytes.Length.Should().BeGreaterThan(3);
        // UTF-8 BOM is EF BB BF — must not appear at the start.
        (bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF).Should().BeFalse();
    }

    // --- helpers ---

    private async Task<string> RenderAsync(ScanReport report)
    {
        using var stream = new MemoryStream();
        await _writer.WriteAsync(report, stream, CancellationToken.None);
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static ScanReport BuildEmptyReport() =>
        new("/repo", DateTimeOffset.UtcNow, "0.1.0", ScanResult.Empty(SecurityScore.Perfect));

    private static ScanReport BuildReportWithScore(SecurityScore score) =>
        new("/repo", DateTimeOffset.UtcNow, "0.1.0",
            new ScanResult(Array.Empty<Finding>(), FilesScanned: 5, Duration: TimeSpan.FromMilliseconds(120), score));

    private static ScanReport BuildReportWithFindings(params Finding[] findings)
    {
        var result = new ScanResult(findings, FilesScanned: 1, Duration: TimeSpan.FromMilliseconds(50), new SecurityScore(50, "D"));
        return new ScanReport("/repo", DateTimeOffset.UtcNow, "0.1.0", result);
    }

    private static Finding MakeFinding(string ruleId, string title, Severity severity, string file, int line) =>
        new(ruleId, title, "description", severity,
            new FileLocation(file, line, ColumnNumber: 1, Snippet: $"snippet for {title}"),
            Confidence: 0.9);

    private static int CountOccurrences(string haystack, string needle)
    {
        var count = 0;
        var index = 0;
        while ((index = haystack.IndexOf(needle, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += needle.Length;
        }
        return count;
    }
}
