using CodeSentinel.Core.Scanning;

namespace CodeSentinel.Core.Reporting;

public sealed record ScanReport(
    string TargetPath,
    DateTimeOffset ScannedAt,
    string ScannerVersion,
    ScanResult Result);
