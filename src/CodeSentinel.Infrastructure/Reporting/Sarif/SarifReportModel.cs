using System.Text.Json.Serialization;

namespace CodeSentinel.Infrastructure.Reporting.Sarif;

// Internal DTOs implementing the SARIF v2.1.0 output schema.
// Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
// These types are decoupled from domain entities so the SARIF shape can evolve
// independently of the scanner core.

internal sealed record SarifReport(
    [property: JsonPropertyName("$schema")] string Schema,
    string Version,
    IReadOnlyList<SarifRun> Runs);

internal sealed record SarifRun(
    SarifTool Tool,
    IReadOnlyList<SarifResult> Results);

internal sealed record SarifTool(SarifDriver Driver);

internal sealed record SarifDriver(
    string Name,
    string Version,
    string InformationUri,
    IReadOnlyList<SarifRuleDescriptor> Rules);

internal sealed record SarifRuleDescriptor(
    string Id,
    string Name,
    SarifMessage ShortDescription,
    SarifMessage FullDescription,
    SarifDefaultConfiguration DefaultConfiguration);

internal sealed record SarifDefaultConfiguration(string Level);

internal sealed record SarifResult(
    string RuleId,
    string Level,
    SarifMessage Message,
    IReadOnlyList<SarifLocation> Locations,
    SarifProperties? Properties);

internal sealed record SarifLocation(SarifPhysicalLocation PhysicalLocation);

internal sealed record SarifPhysicalLocation(
    SarifArtifactLocation ArtifactLocation,
    SarifRegion Region);

internal sealed record SarifArtifactLocation(string Uri);

internal sealed record SarifRegion(
    int StartLine,
    int StartColumn,
    SarifSnippet? Snippet);

internal sealed record SarifSnippet(string Text);

internal sealed record SarifMessage(string Text);

internal sealed record SarifProperties(double Confidence);
