using System.Text.RegularExpressions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;

namespace CodeSentinel.Infrastructure.Rules.Heuristics;

internal sealed class ShannonEntropyRule : IDetectionRule
{
    private const double EntropyThreshold = 4.5;
    private const int MinCandidateLength = 20;

    // Lower confidence than pattern-based rules: entropy is a heuristic and produces more false positives.
    private const double RuleConfidence = 0.6;

    // Targets quoted string literals long enough to be candidate secrets.
    private static readonly Regex CandidatePattern = new(
        @"[""']([^""'\s\\]{" + MinCandidateLength + @",})[""']",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        matchTimeout: TimeSpan.FromSeconds(1));

    public RuleMetadata Metadata { get; } = new(
        Id: "CS900",
        Title: "High-Entropy String",
        Description: "A string with high Shannon entropy was detected. This is a heuristic indicator of an embedded secret or credential.",
        Category: RuleCategory.Secret,
        DefaultSeverity: Severity.Medium);

    public ValueTask<IReadOnlyList<Finding>> AnalyzeAsync(ScannableFile file, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        for (var i = 0; i < file.Lines.Count; i++)
        {
            if (cancellationToken.IsCancellationRequested)
                break;

            var line = file.Lines[i];
            foreach (Match match in CandidatePattern.Matches(line))
            {
                var candidate = match.Groups[1].Value;
                if (ComputeEntropy(candidate) >= EntropyThreshold)
                {
                    findings.Add(new Finding(
                        Metadata.Id,
                        Metadata.Title,
                        Metadata.Description,
                        Metadata.DefaultSeverity,
                        new FileLocation(
                            file.RelativePath,
                            LineNumber: i + 1,
                            ColumnNumber: match.Index + 1,
                            Snippet: RedactSnippet(line, match)),
                        RuleConfidence));
                }
            }
        }

        return ValueTask.FromResult<IReadOnlyList<Finding>>(findings);
    }

    private static double ComputeEntropy(string value)
    {
        var freq = new Dictionary<char, int>(value.Length);
        foreach (var c in value)
            freq[c] = freq.GetValueOrDefault(c) + 1;

        var entropy = 0.0;
        foreach (var count in freq.Values)
        {
            var p = (double)count / value.Length;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private static string RedactSnippet(string line, Match match)
    {
        var snippet = line.Length <= 200 ? line.TrimEnd() : line[..200].TrimEnd() + "...";
        var candidateValue = match.Groups[1].Value;

        var redactedIndex = snippet.IndexOf(candidateValue, StringComparison.Ordinal);
        if (redactedIndex < 0)
            return snippet;

        return snippet[..redactedIndex] + "[REDACTED]" + snippet[(redactedIndex + candidateValue.Length)..];
    }
}
