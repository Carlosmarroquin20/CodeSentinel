using CodeSentinel.Core.Findings;

namespace CodeSentinel.Application.Scanning;

// Several secret rules routinely fire on the same characters: a GitHub token assigned
// to a variable named "token" matches the GitHub rule, the generic credential rule and
// the entropy heuristic. Reporting all three inflates the finding count and triples the
// score penalty for a single leak. Within a line, a secret finding is dropped when a
// higher-severity secret finding covers an overlapping span. Distinct secrets on the
// same line, findings without an end column, and non-secret findings are kept.
internal static class OverlappingSecretFilter
{
    // Expects findings sorted by file path and line number.
    public static List<Finding> Apply(List<Finding> findings, IReadOnlySet<string> secretRuleIds)
    {
        var kept = new List<Finding>(findings.Count);
        var start = 0;

        while (start < findings.Count)
        {
            var end = start + 1;
            while (end < findings.Count && IsSameLine(findings[start], findings[end]))
                end++;

            for (var i = start; i < end; i++)
            {
                if (!IsShadowed(findings, i, start, end, secretRuleIds))
                    kept.Add(findings[i]);
            }

            start = end;
        }

        return kept;
    }

    private static bool IsShadowed(List<Finding> findings, int index, int start, int end, IReadOnlySet<string> secretRuleIds)
    {
        var candidate = findings[index];
        if (!secretRuleIds.Contains(candidate.RuleId))
            return false;

        for (var i = start; i < end; i++)
        {
            var other = findings[i];
            if (i != index &&
                other.Severity > candidate.Severity &&
                secretRuleIds.Contains(other.RuleId) &&
                Overlaps(candidate.Location, other.Location))
            {
                return true;
            }
        }

        return false;
    }

    private static bool Overlaps(FileLocation a, FileLocation b) =>
        a.EndColumnNumber is { } aEnd &&
        b.EndColumnNumber is { } bEnd &&
        a.ColumnNumber < bEnd &&
        b.ColumnNumber < aEnd;

    private static bool IsSameLine(Finding a, Finding b) =>
        a.Location.LineNumber == b.Location.LineNumber &&
        string.Equals(a.Location.FilePath, b.Location.FilePath, StringComparison.Ordinal);
}
