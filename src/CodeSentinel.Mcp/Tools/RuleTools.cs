using System.ComponentModel;
using CodeSentinel.Application.Abstractions;
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
}
