namespace CodeSentinel.Infrastructure.Reporting.Json;

// Internal DTOs that define the JSON output contract.
// These types are decoupled from the domain model so the serialization shape
// can evolve independently of Core entities.

internal sealed record JsonReport(
    string Scanner,
    string Version,
    DateTimeOffset ScannedAt,
    string Target,
    JsonSummary Summary,
    IReadOnlyList<JsonFinding> Findings);

internal sealed record JsonSummary(
    int FilesScanned,
    int FindingCount,
    string Duration,
    JsonScore Score);

internal sealed record JsonScore(int Value, string Grade);

internal sealed record JsonFinding(
    string RuleId,
    string Title,
    string Description,
    string Severity,
    double Confidence,
    JsonLocation Location);

internal sealed record JsonLocation(
    string File,
    int Line,
    int Column,
    string? Snippet);
