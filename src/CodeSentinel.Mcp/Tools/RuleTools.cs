using System.ComponentModel;
using CodeSentinel.Application.Abstractions;
using ModelContextProtocol;
using ModelContextProtocol.Server;

namespace CodeSentinel.Mcp.Tools;

[McpServerToolType]
internal sealed class RuleTools
{
    private readonly IRuleProvider _ruleProvider;

    public RuleTools(IRuleProvider ruleProvider)
    {
        _ruleProvider = ruleProvider;
    }

    [McpServerTool(
        Name = "list_rules",
        Title = "List CodeSentinel detection rules",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = false,
        UseStructuredContent = true)]
    [Description(
        "Lists every detection rule CodeSentinel applies when scanning. Each entry has the rule id "
        + "(for example CS001), a short title, the category (Secret, InsecurePattern or Misconfiguration), "
        + "the severity it reports (Info, Low, Medium, High or Critical) and a one-sentence description. "
        + "Rules are sorted by id. Use it to see what a scan can find, or to look up a rule id that "
        + "appears in scan_path results. Takes no arguments and does not read any files.")]
    public RuleListResult ListRules()
    {
        var rules = _ruleProvider.GetRules()
            .Select(rule => rule.Metadata)
            .OrderBy(metadata => metadata.Id, StringComparer.Ordinal)
            .Select(metadata => new RuleSummary(
                metadata.Id,
                metadata.Title,
                metadata.Category.ToString(),
                metadata.DefaultSeverity.ToString(),
                metadata.Description))
            .ToList();

        return new RuleListResult(rules.Count, rules);
    }

    [McpServerTool(
        Name = "explain_rule",
        Title = "Explain a CodeSentinel rule",
        ReadOnly = true,
        Destructive = false,
        Idempotent = true,
        OpenWorld = false,
        UseStructuredContent = true)]
    [Description(
        "Explains one detection rule: what it matches, why that is a security risk, and the steps to fix "
        + "a finding, in the order they should be done (for leaked credentials, revoking comes before "
        + "editing the code). Also returns the rule's title, category and severity, and how to silence a "
        + "false positive. Use it after scan_path to decide how to fix a finding. Does not read any files.")]
    public ExplainRuleResult ExplainRule(
        [Description("Rule id as shown by scan_path or list_rules, for example CS005. Case-insensitive.")]
        string ruleId)
    {
        var id = ruleId?.Trim() ?? string.Empty;
        var metadata = _ruleProvider.GetRules()
            .Select(rule => rule.Metadata)
            .FirstOrDefault(m => string.Equals(m.Id, id, StringComparison.OrdinalIgnoreCase));

        if (metadata is null)
        {
            var known = _ruleProvider.GetRules()
                .Select(rule => rule.Metadata.Id)
                .Order(StringComparer.Ordinal);
            throw new McpException($"Unknown rule id '{ruleId}'. Known rules: {string.Join(", ", known)}.");
        }

        // Every built-in rule has an entry (enforced by a test); a rule added without one
        // still gets its metadata rather than an error.
        var guidance = RuleGuidanceCatalog.Find(metadata.Id)
            ?? new RuleGuidance(metadata.Description, metadata.Description, []);

        return new ExplainRuleResult(
            Id: metadata.Id,
            Title: metadata.Title,
            Category: metadata.Category.ToString(),
            Severity: metadata.DefaultSeverity.ToString(),
            Summary: metadata.Description,
            Detects: guidance.Detects,
            Risk: guidance.Risk,
            Remediation: guidance.Remediation,
            Suppression:
                $"If a finding is a false positive, add a comment containing 'codesentinel:ignore {metadata.Id}' "
                + "on the same line, or exclude the file with a glob in .codesentinelignore. Naming the rule id "
                + "keeps the other rules active on that line.");
    }
}
