using CodeSentinel.Application.Abstractions;
using CodeSentinel.Mcp.Tools;
using Microsoft.Extensions.DependencyInjection;

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

    public void Dispose() => _provider.Dispose();
}
