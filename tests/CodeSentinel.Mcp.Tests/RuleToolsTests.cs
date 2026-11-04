using CodeSentinel.Application.Abstractions;
using CodeSentinel.Mcp.Tools;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol;

namespace CodeSentinel.Mcp.Tests;

public sealed class RuleToolsTests : IDisposable
{
    private readonly ServiceProvider _provider = TestServices.Build();

    private RuleTools CreateTools() =>
        ActivatorUtilities.CreateInstance<RuleTools>(_provider);

    [Fact]
    public void ListRules_ReturnsEveryRegisteredRule()
    {
        var registered = _provider.GetRequiredService<IRuleProvider>().GetRules()
            .Select(rule => rule.Metadata.Id);

        var result = CreateTools().ListRules();

        result.Rules.Select(rule => rule.Id).Should().BeEquivalentTo(registered);
        result.Count.Should().Be(result.Rules.Count);
    }

    [Fact]
    public void ListRules_SortsRulesById()
    {
        var result = CreateTools().ListRules();

        result.Rules.Select(rule => rule.Id).Should().BeInAscendingOrder(StringComparer.Ordinal);
    }

    [Fact]
    public void ListRules_ReportsCategoryAndSeverityAsNames()
    {
        var result = CreateTools().ListRules();

        result.Rules.Should().ContainEquivalentOf(new
        {
            Id = "CS001",
            Title = "AWS Access Key ID",
            Category = "Secret",
            Severity = "Critical",
        });
        result.Rules.Should().ContainEquivalentOf(new
        {
            Id = "CS101",
            Category = "InsecurePattern",
            Severity = "Medium",
        });
    }

    [Fact]
    public void ListRules_IncludesADescriptionForEveryRule()
    {
        var result = CreateTools().ListRules();

        result.Rules.Should().OnlyContain(rule => !string.IsNullOrWhiteSpace(rule.Description));
    }

    [Fact]
    public void ExplainRule_HasGuidanceForEveryRegisteredRule()
    {
        var tools = CreateTools();

        foreach (var id in RegisteredRuleIds())
        {
            var result = tools.ExplainRule(id);

            result.Detects.Should().NotBe(result.Summary, because: $"{id} needs its own guidance entry");
            result.Risk.Should().NotBeNullOrWhiteSpace();
            result.Remediation.Should().HaveCountGreaterThanOrEqualTo(2, because: $"{id} needs remediation steps");
        }
    }

    [Fact]
    public void GuidanceCatalog_OnlyDescribesRegisteredRules()
    {
        RuleGuidanceCatalog.RuleIds.Should().BeEquivalentTo(RegisteredRuleIds());
    }

    [Fact]
    public void ExplainRule_ReturnsMetadataAndGuidance()
    {
        var result = CreateTools().ExplainRule("CS001");

        result.Id.Should().Be("CS001");
        result.Title.Should().Be("AWS Access Key ID");
        result.Category.Should().Be("Secret");
        result.Severity.Should().Be("Critical");
        result.Summary.Should().StartWith("An AWS access key ID was detected");
        result.Detects.Should().Contain("AKIA");
        result.Remediation[0].Should().Contain("Deactivate");
    }

    [Theory]
    [InlineData("cs005")]
    [InlineData(" CS005 ")]
    public void ExplainRule_AcceptsIdsInAnyCaseAndWithSpaces(string ruleId)
    {
        CreateTools().ExplainRule(ruleId).Id.Should().Be("CS005");
    }

    [Fact]
    public void ExplainRule_SuppressionNamesTheRule()
    {
        CreateTools().ExplainRule("CS900").Suppression.Should().Contain("codesentinel:ignore CS900");
    }

    [Theory]
    [InlineData("CS999")]
    [InlineData("")]
    public void ExplainRule_UnknownId_ListsKnownRules(string ruleId)
    {
        var act = () => CreateTools().ExplainRule(ruleId);

        act.Should().Throw<McpException>().WithMessage("Unknown rule id*Known rules: CS001, CS002*CS900.");
    }

    private IEnumerable<string> RegisteredRuleIds() =>
        _provider.GetRequiredService<IRuleProvider>().GetRules().Select(rule => rule.Metadata.Id);

    public void Dispose() => _provider.Dispose();
}
