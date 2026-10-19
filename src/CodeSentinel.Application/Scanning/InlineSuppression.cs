using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Application.Scanning;

// Lets a line opt out of findings with a comment, the same way gitleaks:allow or
// "pragma: allowlist secret" work in other scanners:
//
//   api_key = "test-fixture-value"  # codesentinel:ignore
//   token = "..."                   // codesentinel:ignore CS005, CS900
//
// Without rule IDs every finding on the line is dropped; with IDs only those rules are.
internal static partial class InlineSuppression
{
    [GeneratedRegex(
        @"codesentinel:ignore(?<ids>(?:[ \t]*,?[ \t]*CS\d{3})*)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 1000)]
    private static partial Regex Marker();

    [GeneratedRegex(@"CS\d{3}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
    private static partial Regex RuleId();

    public static List<Finding> Apply(ScannableFile file, List<Finding> findings, out int suppressed)
    {
        suppressed = 0;
        if (findings.Count == 0)
            return findings;

        var kept = new List<Finding>(findings.Count);
        foreach (var finding in findings)
        {
            if (IsSuppressed(file, finding))
                suppressed++;
            else
                kept.Add(finding);
        }

        return kept;
    }

    private static bool IsSuppressed(ScannableFile file, Finding finding)
    {
        var index = finding.Location.LineNumber - 1;
        if (index < 0 || index >= file.Lines.Count)
            return false;

        var line = file.Lines[index];
        if (!line.Contains("codesentinel:ignore", StringComparison.OrdinalIgnoreCase))
            return false;

        var marker = Marker().Match(line);
        if (!marker.Success)
            return false;

        var ids = marker.Groups["ids"].Value;
        if (ids.Length == 0)
            return true;

        foreach (Match id in RuleId().Matches(ids))
        {
            if (string.Equals(id.Value, finding.RuleId, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
