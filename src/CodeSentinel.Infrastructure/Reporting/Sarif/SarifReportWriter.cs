using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using CodeSentinel.Application.Abstractions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;
using CodeSentinel.Core.Reporting;

namespace CodeSentinel.Infrastructure.Reporting.Sarif;

internal sealed class SarifReportWriter : IReportWriter
{
    private const string SchemaUrl =
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
    private const string SarifVersion = "2.1.0";
    private const string ToolName = "CodeSentinel";

    // Resolved at startup from AssemblyMetadata injected by Directory.Build.props,
    // so the project URL has a single source of truth in the MSBuild layer.
    private static readonly string ToolInformationUri = ResolveProjectUrl();

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly IRuleProvider _ruleProvider;

    public SarifReportWriter(IRuleProvider ruleProvider)
    {
        _ruleProvider = ruleProvider;
    }

    public string Format => "sarif";

    public Task WriteAsync(ScanReport report, Stream output, CancellationToken cancellationToken)
    {
        var model = MapToModel(report);
        return JsonSerializer.SerializeAsync(output, model, SerializerOptions, cancellationToken);
    }

    private SarifReport MapToModel(ScanReport report)
    {
        var allRules = _ruleProvider.GetRules()
            .Select(r => r.Metadata)
            .OrderBy(m => m.Id, StringComparer.Ordinal)
            .Select(MapRuleDescriptor)
            .ToList();

        var results = report.Result.Findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Location.FilePath, StringComparer.Ordinal)
            .ThenBy(f => f.Location.LineNumber)
            .Select(MapResult)
            .ToList();

        return new SarifReport(
            Schema: SchemaUrl,
            Version: SarifVersion,
            Runs: [
                new SarifRun(
                    Tool: new SarifTool(new SarifDriver(
                        Name: ToolName,
                        Version: report.ScannerVersion,
                        InformationUri: ToolInformationUri,
                        Rules: allRules)),
                    Results: results),
            ]);
    }

    private static SarifRuleDescriptor MapRuleDescriptor(RuleMetadata metadata) => new(
        Id: metadata.Id,
        Name: metadata.Title,
        ShortDescription: new SarifMessage(metadata.Title),
        FullDescription: new SarifMessage(metadata.Description),
        DefaultConfiguration: new SarifDefaultConfiguration(MapSeverityToLevel(metadata.DefaultSeverity)));

    private static SarifResult MapResult(Finding finding) => new(
        RuleId: finding.RuleId,
        Level: MapSeverityToLevel(finding.Severity),
        Message: new SarifMessage(finding.Title),
        Locations: [
            new SarifLocation(new SarifPhysicalLocation(
                ArtifactLocation: new SarifArtifactLocation(NormalizeUri(finding.Location.FilePath)),
                Region: new SarifRegion(
                    StartLine: Math.Max(1, finding.Location.LineNumber),
                    StartColumn: Math.Max(1, finding.Location.ColumnNumber),
                    Snippet: string.IsNullOrEmpty(finding.Location.Snippet)
                        ? null
                        : new SarifSnippet(finding.Location.Snippet)))),
        ],
        Properties: new SarifProperties(finding.Confidence));

    // SARIF level vocabulary: "error" | "warning" | "note" | "none".
    // Critical and High map to "error" so they surface in GitHub's default code-scanning
    // view; Medium becomes "warning"; Low and Info degrade to "note" and "none".
    private static string MapSeverityToLevel(Severity severity) => severity switch
    {
        Severity.Critical => "error",
        Severity.High     => "error",
        Severity.Medium   => "warning",
        Severity.Low      => "note",
        _                 => "none",
    };

    // SARIF artifact URIs must use forward slashes regardless of host platform.
    private static string NormalizeUri(string path) => path.Replace('\\', '/');

    // Looks up the project URL injected as AssemblyMetadata from Directory.Build.props.
    // Falls back to a constant if the attribute is missing for any reason (e.g., in an
    // unusual build configuration).
    private static string ResolveProjectUrl()
    {
        const string Fallback = "https://github.com/Carlosmarroquin20/CodeSentinel";

        var value = typeof(SarifReportWriter).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => string.Equals(a.Key, "CodeSentinel.ProjectUrl", StringComparison.Ordinal))
            ?.Value;

        return string.IsNullOrWhiteSpace(value) ? Fallback : value;
    }
}
