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
