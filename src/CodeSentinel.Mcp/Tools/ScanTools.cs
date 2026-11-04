using System.ComponentModel;
using CodeSentinel.Application.Abstractions;
using CodeSentinel.Core.Findings;
using CodeSentinel.Core.Scanning;
using CodeSentinel.Mcp.Security;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace CodeSentinel.Mcp.Tools;

[McpServerToolType]
internal sealed class ScanTools
{
    public const int DefaultMaxFindings = 50;
    public const int MaxFindingsLimit = 500;

    private readonly ScanPathValidator _pathValidator;
    private readonly IScanOrchestrator _orchestrator;
    private readonly IIgnoreFileReader _ignoreFileReader;

    public ScanTools(
        ScanPathValidator pathValidator,
        IScanOrchestrator orchestrator,
        IIgnoreFileReader ignoreFileReader)
    {
        _pathValidator = pathValidator;
        _orchestrator = orchestrator;
        _ignoreFileReader = ignoreFileReader;
    }

    [McpServerTool(
        Name = "scan_path",
        Title = "Scan a local directory for secrets and insecure code",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = false,
        UseStructuredContent = true)]
    [Description(
        "Scans a local directory with CodeSentinel and reports exposed secrets (cloud keys, tokens, "
        + "hardcoded passwords, private keys) and insecure patterns such as MD5 or SHA-1 hashing. "
        + "Returns a 0-100 security score with a letter grade (A-F), the number of files scanned, "
        + "finding counts per severity, and a list of findings with rule id, severity, file path "
        + "relative to the scanned directory, 1-based line and column, a message and a code snippet. "
        + "Secret values in snippets are always replaced with [REDACTED]; open the file at the given "
        + "line if you need the surrounding code. Findings are ordered from most to least severe and "
        + "the list is cut at maxFindings; the score and the per-severity counts always cover every "
        + "finding, and 'truncated' tells you whether some were left out. Only directories inside the "
        + "server's allowed roots can be scanned; the error message lists those roots. Git URLs are "
        + "not supported. Files are only read, never modified. Use explain_rule for remediation advice.")]
    public async Task<ScanPathResult> ScanPathAsync(
        [Description(
            "Directory to scan. An absolute path, or a path relative to the first allowed root "
            + "(usually the workspace the server was started in), for example \".\" or \"src\".")]
        string path,
        [Description(
            "Only return findings at or above this severity: Info, Low, Medium, High or Critical "
            + "(case-insensitive). Omit to return every severity. Does not change the score.")]
        string? minSeverity = null,
        [Description(
            "Maximum number of findings to return, from 0 to 500. Defaults to 50. Use 0 to get only "
            + "the score and the counts.")]
        int maxFindings = DefaultMaxFindings,
        [Description(
            "Apply the .codesentinelignore file in the scanned directory. Defaults to true. Set it "
            + "to false for code you do not trust, since that file can hide files from the scan.")]
        bool useIgnoreFile = true,
        [Description(
            "Honour codesentinel:ignore comments that silence findings on their line. Defaults to "
            + "true. Set it to false for code you do not trust.")]
        bool honorInlineSuppressions = true,
        CancellationToken cancellationToken = default)
    {
        var threshold = ParseSeverity(minSeverity);
        if (maxFindings is < 0 or > MaxFindingsLimit)
            throw new McpException($"maxFindings must be between 0 and {MaxFindingsLimit}; got {maxFindings}.");

        var root = _pathValidator.Resolve(path);
        var ignoreGlobs = useIgnoreFile ? _ignoreFileReader.ReadPatterns(root) : [];
        var request = new ScanRequest(root, ignoreGlobs, honorInlineSuppressions);

        var result = await _orchestrator.ExecuteAsync(request, cancellationToken).ConfigureAwait(false);

        // OrderByDescending is stable, so findings of equal severity keep the
        // orchestrator's path, line and column order.
        var matching = result.Findings
            .Where(finding => threshold is null || finding.Severity >= threshold.Value)
            .OrderByDescending(finding => finding.Severity)
            .ToList();
        var returned = matching.Take(maxFindings).Select(ToSummary).ToList();

        return new ScanPathResult(
            Path: root,
            FilesScanned: result.FilesScanned,
            Score: result.Score.Value,
            Grade: result.Score.Grade,
            FindingsBySeverity: CountBySeverity(result.Findings),
            TotalFindings: result.Findings.Count,
            MatchingFindings: matching.Count,
            ReturnedFindings: returned.Count,
            Truncated: returned.Count < matching.Count,
            Findings: returned);
    }

    // Enum.TryParse also accepts numbers such as "4" or "99", so only the names are allowed.
    private static Severity? ParseSeverity(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        foreach (var severity in Enum.GetValues<Severity>())
        {
            if (string.Equals(severity.ToString(), value.Trim(), StringComparison.OrdinalIgnoreCase))
                return severity;
        }

        throw new McpException(
            $"Unknown severity '{value}'. Use one of: {string.Join(", ", Enum.GetNames<Severity>())}.");
    }

    private static SeverityCounts CountBySeverity(IReadOnlyList<Finding> findings) =>
        new(
            Critical: findings.Count(f => f.Severity == Severity.Critical),
            High: findings.Count(f => f.Severity == Severity.High),
            Medium: findings.Count(f => f.Severity == Severity.Medium),
            Low: findings.Count(f => f.Severity == Severity.Low),
            Info: findings.Count(f => f.Severity == Severity.Info));

    private static FindingSummary ToSummary(Finding finding) =>
        new(
            RuleId: finding.RuleId,
            Severity: finding.Severity.ToString(),
            File: ToForwardSlashes(finding.Location.FilePath),
            Line: finding.Location.LineNumber,
            Column: finding.Location.ColumnNumber,
            Message: finding.Description,
            Snippet: finding.Location.Snippet,
            Confidence: finding.Confidence);

    // A backslash is a legal file name character on Linux and macOS, so it is only
    // treated as a separator where it is one.
    private static string ToForwardSlashes(string relativePath) =>
        Path.DirectorySeparatorChar == '\\' ? relativePath.Replace('\\', '/') : relativePath;
}
