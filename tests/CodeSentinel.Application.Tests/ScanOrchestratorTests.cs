using CodeSentinel.Application.Abstractions;
using CodeSentinel.Application.DependencyInjection;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Findings;
using CodeSentinel.Core.Scanning;
using CodeSentinel.Infrastructure.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;

namespace CodeSentinel.Application.Tests;

public class ScanOrchestratorTests : IAsyncDisposable
{
    private readonly string _tempDir = Directory.CreateTempSubdirectory("cs-app-test-").FullName;

    [Fact]
    public async Task ExecuteAsync_OverEmptyDirectory_ReturnsPerfectScore()
    {
        await using var provider = BuildServiceProvider();
        var orchestrator = provider.GetRequiredService<IScanOrchestrator>();

        var result = await orchestrator.ExecuteAsync(
            ScanRequest.ForPath(_tempDir),
            CancellationToken.None);

        result.Findings.Should().BeEmpty();
        result.FilesScanned.Should().Be(0);
        result.Score.Value.Should().Be(100);
        result.Score.Grade.Should().Be("A");
    }

    [Fact]
    public async Task ExecuteAsync_WhenOneRuleThrows_KeepsResultsFromOtherRules()
    {
        File.WriteAllText(Path.Combine(_tempDir, "app.py"), "x = 1");

        var ruleProvider = Substitute.For<IRuleProvider>();
        ruleProvider.GetRules().Returns([new ThrowingRule(), new SingleFindingRule()]);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCodeSentinelApplication();
        services.AddCodeSentinelInfrastructure();
        services.AddSingleton(ruleProvider);
        await using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IScanOrchestrator>()
            .ExecuteAsync(ScanRequest.ForPath(_tempDir), CancellationToken.None);

        result.FilesScanned.Should().Be(1);
        result.Findings.Should().ContainSingle().Which.RuleId.Should().Be("T002");
    }

    [Fact]
    public async Task ExecuteAsync_DropsSecretFindingCoveredByHigherSeveritySecret()
    {
        var result = await ScanWithRulesAsync(
            new SpanRule("T100", RuleCategory.Secret, Severity.Critical, start: 10, end: 30),
            new SpanRule("T200", RuleCategory.Secret, Severity.High, start: 1, end: 31),
            new SpanRule("T300", RuleCategory.Secret, Severity.Medium, start: 9, end: 31));

        result.Findings.Select(f => f.RuleId).Should().Equal("T100");
    }

    [Fact]
    public async Task ExecuteAsync_KeepsSecretsThatDoNotOverlap()
    {
        var result = await ScanWithRulesAsync(
            new SpanRule("T100", RuleCategory.Secret, Severity.Critical, start: 1, end: 10),
            new SpanRule("T200", RuleCategory.Secret, Severity.High, start: 20, end: 40));

        result.Findings.Select(f => f.RuleId).Should().BeEquivalentTo("T100", "T200");
    }

    [Fact]
    public async Task ExecuteAsync_KeepsNonSecretFindingsOnTheSameSpan()
    {
        var result = await ScanWithRulesAsync(
            new SpanRule("T100", RuleCategory.Secret, Severity.Critical, start: 1, end: 30),
            new SpanRule("T900", RuleCategory.InsecurePattern, Severity.Medium, start: 1, end: 30));

        result.Findings.Select(f => f.RuleId).Should().BeEquivalentTo("T100", "T900");
    }

    [Fact]
    public async Task ExecuteAsync_ReportsAGitHubTokenOnce()
    {
        // Built at runtime so the repository does not contain a token-shaped literal.
        var token = "ghp" + "_" + new string('a', 18) + new string('Z', 18);
        File.WriteAllText(Path.Combine(_tempDir, "app.js"), $"const token = \"{token}\";");

        await using var provider = BuildServiceProvider();
        var result = await provider.GetRequiredService<IScanOrchestrator>()
            .ExecuteAsync(ScanRequest.ForPath(_tempDir), CancellationToken.None);

        result.Findings.Should().ContainSingle().Which.RuleId.Should().Be("CS006");
    }

    private async Task<ScanResult> ScanWithRulesAsync(params IDetectionRule[] rules)
    {
        File.WriteAllText(Path.Combine(_tempDir, "app.py"), new string('x', 40));

        var ruleProvider = Substitute.For<IRuleProvider>();
        ruleProvider.GetRules().Returns(rules);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCodeSentinelApplication();
        services.AddCodeSentinelInfrastructure();
        services.AddSingleton(ruleProvider);
        await using var provider = services.BuildServiceProvider();

        return await provider.GetRequiredService<IScanOrchestrator>()
            .ExecuteAsync(ScanRequest.ForPath(_tempDir), CancellationToken.None);
    }

    private sealed class SpanRule(string id, RuleCategory category, Severity severity, int start, int end) : IDetectionRule
    {
        public RuleMetadata Metadata { get; } = new(id, "t", "d", category, severity);

        public ValueTask<IReadOnlyList<Finding>> AnalyzeAsync(ScannableFile file, CancellationToken cancellationToken) =>
            ValueTask.FromResult<IReadOnlyList<Finding>>(
            [
                new Finding(Metadata.Id, "t", "d", severity, new FileLocation(file.RelativePath, 1, start, null, end), 1.0),
            ]);
    }

    private sealed class ThrowingRule : IDetectionRule
    {
        public RuleMetadata Metadata { get; } = new("T001", "t", "d", RuleCategory.Secret, Severity.Low);

        public ValueTask<IReadOnlyList<Finding>> AnalyzeAsync(ScannableFile file, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("boom");
    }

    private sealed class SingleFindingRule : IDetectionRule
    {
        public RuleMetadata Metadata { get; } = new("T002", "t", "d", RuleCategory.Secret, Severity.Low);

        public ValueTask<IReadOnlyList<Finding>> AnalyzeAsync(ScannableFile file, CancellationToken cancellationToken) =>
            ValueTask.FromResult<IReadOnlyList<Finding>>(
            [
                new Finding(Metadata.Id, "t", "d", Severity.Low, new FileLocation(file.RelativePath, 1, 1, null), 1.0),
            ]);
    }

    public async ValueTask DisposeAsync()
    {
        await Task.Run(() => Directory.Delete(_tempDir, recursive: true));
        GC.SuppressFinalize(this);
    }

    private static ServiceProvider BuildServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCodeSentinelApplication();
        services.AddCodeSentinelInfrastructure();
        return services.BuildServiceProvider();
    }
}
