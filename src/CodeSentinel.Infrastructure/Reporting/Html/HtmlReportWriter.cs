using System.Globalization;
using System.Net;
using System.Text;
using CodeSentinel.Application.Abstractions;
using CodeSentinel.Core.Findings;
using CodeSentinel.Core.Reporting;
using CodeSentinel.Core.Scanning;

namespace CodeSentinel.Infrastructure.Reporting.Html;

internal sealed class HtmlReportWriter : IReportWriter
{
    // No-BOM UTF-8 keeps the file clean for browsers and downstream tooling.
    private static readonly Encoding Utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    public string Format => "html";

    public async Task WriteAsync(ScanReport report, Stream output, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(output);

        var html = BuildHtml(report);
        var bytes = Utf8NoBom.GetBytes(html);
        await output.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
    }

    private static string BuildHtml(ScanReport report)
    {
        var sb = new StringBuilder(capacity: 16_384);

        sb.Append(HtmlReportTemplate.HeadStart);
        sb.Append(HtmlReportTemplate.EmbeddedCss);
        sb.Append(HtmlReportTemplate.HeadEnd);
        sb.Append("<body><div class=\"container\">");

        AppendHeader(sb, report);
        AppendSummary(sb, report.Result);
        AppendFindings(sb, report.Result.Findings);

        sb.Append("</div></body></html>");
        return sb.ToString();
    }

    private static void AppendHeader(StringBuilder sb, ScanReport report)
    {
        sb.Append("<header>");
        sb.Append("<h1>CodeSentinel Security Report</h1>");
        sb.Append("<div class=\"meta\">");
        sb.Append("<span><strong>Target:</strong> ").Append(Encode(report.TargetPath)).Append("</span>");
        sb.Append("<span><strong>Scanned:</strong> ")
          .Append(Encode(report.ScannedAt.ToString("u", CultureInfo.InvariantCulture)))
          .Append("</span>");
        sb.Append("<span><strong>Version:</strong> ").Append(Encode(report.ScannerVersion)).Append("</span>");
        sb.Append("</div></header>");
    }

    private static void AppendSummary(StringBuilder sb, ScanResult result)
    {
        var gradeClass = "score-" + Encode(result.Score.Grade);

        sb.Append("<section class=\"summary\">");
        sb.Append("<div class=\"score ").Append(gradeClass).Append("\">");
        sb.Append("<div class=\"score-value\">")
          .Append(result.Score.Value.ToString(CultureInfo.InvariantCulture))
          .Append("</div>");
        sb.Append("<div class=\"score-grade\">Grade ").Append(Encode(result.Score.Grade)).Append("</div>");
        sb.Append("</div>");

        sb.Append("<div class=\"stats\">");
        AppendStat(sb, "Files scanned", result.FilesScanned.ToString(CultureInfo.InvariantCulture));
        AppendStat(sb, "Findings", result.Findings.Count.ToString(CultureInfo.InvariantCulture));
        AppendStat(sb, "Duration", result.Duration.ToString(@"hh\:mm\:ss\.fff", CultureInfo.InvariantCulture));
        sb.Append("</div>");
        sb.Append("</section>");
    }

    private static void AppendStat(StringBuilder sb, string label, string value)
    {
        sb.Append("<div class=\"stat\">");
        sb.Append("<div class=\"stat-label\">").Append(Encode(label)).Append("</div>");
        sb.Append("<div class=\"stat-value\">").Append(Encode(value)).Append("</div>");
        sb.Append("</div>");
    }

    private static void AppendFindings(StringBuilder sb, IReadOnlyList<Finding> findings)
    {
        sb.Append("<section class=\"findings\">");
        sb.Append("<h2>Findings</h2>");

        if (findings.Count == 0)
        {
            sb.Append("<p class=\"no-findings\">No security issues detected.</p>");
        }
        else
        {
            sb.Append("<table><thead><tr>");
            sb.Append("<th>Severity</th><th>Rule</th><th>Title</th><th>Location</th><th>Snippet</th>");
            sb.Append("</tr></thead><tbody>");

            var ordered = findings
                .OrderByDescending(f => f.Severity)
                .ThenBy(f => f.Location.FilePath, StringComparer.Ordinal)
                .ThenBy(f => f.Location.LineNumber);

            foreach (var finding in ordered)
            {
                AppendFindingRow(sb, finding);
            }

            sb.Append("</tbody></table>");
        }

        sb.Append("</section>");
    }

    private static void AppendFindingRow(StringBuilder sb, Finding f)
    {
        var severityName = f.Severity.ToString();
        var badgeClass = "badge-" + severityName.ToLowerInvariant();

        sb.Append("<tr>");
        sb.Append("<td><span class=\"badge ").Append(badgeClass).Append("\">")
          .Append(Encode(severityName)).Append("</span></td>");
        sb.Append("<td><span class=\"rule-id\">").Append(Encode(f.RuleId)).Append("</span></td>");
        sb.Append("<td>").Append(Encode(f.Title)).Append("</td>");
        sb.Append("<td><span class=\"location\">")
          .Append(Encode(f.Location.FilePath))
          .Append(':')
          .Append(f.Location.LineNumber.ToString(CultureInfo.InvariantCulture))
          .Append("</span></td>");
        sb.Append("<td>");
        if (!string.IsNullOrEmpty(f.Location.Snippet))
        {
            sb.Append("<pre class=\"snippet\">").Append(Encode(f.Location.Snippet)).Append("</pre>");
        }
        sb.Append("</td>");
        sb.Append("</tr>");
    }

    // All user-controlled strings — paths, snippets from scanned files, score grade —
    // pass through this. Findings can contain arbitrary content from the scan target,
    // so missing an encode here would mean XSS in a security report.
    private static string Encode(string value) => WebUtility.HtmlEncode(value);
}
