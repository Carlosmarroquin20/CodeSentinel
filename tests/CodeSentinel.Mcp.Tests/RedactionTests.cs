using System.Text.Json;
using CodeSentinel.Application.Abstractions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Mcp.Security;
using CodeSentinel.Mcp.Tools;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol;

namespace CodeSentinel.Mcp.Tests;

// scan_path relies on the rules' own redaction (ADR 0003). These tests check the
// result the agent receives, serialized the way the SDK sends it.
public sealed class RedactionTests : IDisposable
{
    private readonly ServiceProvider _provider = TestServices.Build();

    private async Task<ScanPathResult> ScanFixtureAsync()
    {
        var roots = AllowedRoots.Parse(
            ["--allowed-root", RepositoryPaths.VulnerableRepo],
            environmentValue: null,
            RepositoryPaths.VulnerableRepo);
        var tools = new ScanTools(
            new ScanPathValidator(roots),
            _provider.GetRequiredService<IScanOrchestrator>(),
            _provider.GetRequiredService<IIgnoreFileReader>());

        return await tools.ScanPathAsync(".", maxFindings: ScanTools.MaxFindingsLimit);
    }

    [Fact]
    public async Task ScanPath_RedactsEverySecretFinding()
    {
        var secretRuleIds = _provider.GetRequiredService<IRuleProvider>().GetRules()
            .Where(rule => rule.Metadata.Category == RuleCategory.Secret)
            .Select(rule => rule.Metadata.Id)
            .ToHashSet(StringComparer.Ordinal);

        var result = await ScanFixtureAsync();
        var secretFindings = result.Findings.Where(finding => secretRuleIds.Contains(finding.RuleId)).ToList();

        secretFindings.Should().HaveCount(15);
        secretFindings.Should().OnlyContain(finding => finding.Snippet!.Contains(FixtureSecrets.Marker));
    }

    [Fact]
    public async Task ScanPath_SerializedResultContainsNoSecretValue()
    {
        var result = await ScanFixtureAsync();
        var recovered = FixtureSecrets.Recover(RepositoryPaths.VulnerableRepo, result.Findings);

        var json = JsonSerializer.Serialize(result, McpJsonUtilities.DefaultOptions);

        recovered.Should().HaveCount(15).And.Contain(FixtureSecrets.Known);
        foreach (var secret in recovered)
            json.Should().NotContain(secret);
    }

    [Fact]
    public async Task ScanPath_KeepsNonSecretSnippetsReadable()
    {
        var result = await ScanFixtureAsync();

        result.Findings.Should().Contain(finding =>
            finding.RuleId == "CS101" && finding.Snippet!.Contains("hashlib.md5", StringComparison.Ordinal));
    }

    public void Dispose() => _provider.Dispose();
}
