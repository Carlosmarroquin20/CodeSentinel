using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Infrastructure.Rules.BuiltIn;

internal abstract class RegexDetectionRule : IDetectionRule
{
    private readonly Regex _pattern;

    protected RegexDetectionRule(Regex pattern)
    {
        _pattern = pattern;
    }

    public abstract RuleMetadata Metadata { get; }

    public ValueTask<IReadOnlyList<Finding>> AnalyzeAsync(ScannableFile file, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        for (var i = 0; i < file.Lines.Count; i++)
        {
            if (cancellationToken.IsCancellationRequested)
                break;

            var line = file.Lines[i];
            foreach (Match match in _pattern.Matches(line))
            {
                findings.Add(BuildFinding(file, lineNumber: i + 1, columnNumber: match.Index + 1, line, match));
            }
        }

        return ValueTask.FromResult<IReadOnlyList<Finding>>(findings);
    }

    protected virtual Finding BuildFinding(
        ScannableFile file, int lineNumber, int columnNumber, string line, Match match)
    {
        var snippet = Metadata.Category == RuleCategory.Secret
            ? Redact(line, match)
            : Truncate(line);

        var confidence = Metadata.Category == RuleCategory.InsecurePattern ? 1.0 : 0.9;

        return new Finding(
            Metadata.Id,
            Metadata.Title,
            Metadata.Description,
            Metadata.DefaultSeverity,
            new FileLocation(file.RelativePath, lineNumber, columnNumber, snippet),
            confidence);
    }

    protected static string Truncate(string value) =>
        value.Length <= 200 ? value.TrimEnd() : value[..200].TrimEnd() + "...";

    // Replaces the matched secret value with [REDACTED] so raw credentials never appear in reports.
    // When a capture group is present it targets the group; otherwise it targets the full match.
    private static string Redact(string line, Match match)
    {
        var target = match.Groups.Count > 1 && match.Groups[1].Success
            ? (Group)match.Groups[1]
            : match;

        if (target.Length == 0)
            return Truncate(line);

        var before = target.Index < line.Length ? line[..target.Index] : string.Empty;
        var after = (target.Index + target.Length) < line.Length
            ? line[(target.Index + target.Length)..]
            : string.Empty;

        return Truncate(before + "[REDACTED]" + after);
    }
}
