using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using CodeSentinel.Application.Abstractions;
using CodeSentinel.Core.Findings;
using CodeSentinel.Core.Reporting;

namespace CodeSentinel.Infrastructure.Reporting.Json;

internal sealed class JsonReportWriter : IReportWriter
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public string Format => "json";

    public Task WriteAsync(ScanReport report, Stream output, CancellationToken cancellationToken)
    {
        var model = MapToModel(report);
        return JsonSerializer.SerializeAsync(output, model, SerializerOptions, cancellationToken);
    }

    private static JsonReport MapToModel(ScanReport report)
    {
        // Sort findings by severity descending so the most critical issues appear first.
        var sortedFindings = report.Result.Findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Location.FilePath)
            .ThenBy(f => f.Location.LineNumber)
            .Select(MapFinding)
            .ToList();

        return new JsonReport(
            Scanner: "CodeSentinel",
            Version: report.ScannerVersion,
            ScannedAt: report.ScannedAt,
            Target: report.TargetPath,
            Summary: new JsonSummary(
                FilesScanned: report.Result.FilesScanned,
                FindingCount: report.Result.Findings.Count,
                Duration: report.Result.Duration.ToString(@"hh\:mm\:ss\.fff", CultureInfo.InvariantCulture),
                Score: new JsonScore(
                    report.Result.Score.Value,
                    report.Result.Score.Grade)),
            Findings: sortedFindings);
    }

    private static JsonFinding MapFinding(Finding f) => new(
        RuleId: f.RuleId,
        Title: f.Title,
        Description: f.Description,
        Severity: f.Severity.ToString(),
        Confidence: f.Confidence,
        Location: new JsonLocation(
            File: f.Location.FilePath,
            Line: f.Location.LineNumber,
            Column: f.Location.ColumnNumber,
            Snippet: f.Location.Snippet));
}
