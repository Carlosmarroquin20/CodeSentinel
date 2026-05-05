using CodeSentinel.Application.Abstractions;
using CodeSentinel.Application.DependencyInjection;
using CodeSentinel.Core.Scanning;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Application.Tests;

public class ScanOrchestratorTests
{
    [Fact]
    public async Task ExecuteAsync_OnEmptyRequest_ReturnsEmptyResultAndPerfectScore()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCodeSentinelApplication();

        await using var provider = services.BuildServiceProvider();
        var orchestrator = provider.GetRequiredService<IScanOrchestrator>();

        var result = await orchestrator.ExecuteAsync(
            ScanRequest.ForPath(Path.GetTempPath()),
            CancellationToken.None);

        result.Findings.Should().BeEmpty();
        result.FilesScanned.Should().Be(0);
        result.Score.Value.Should().Be(100);
        result.Score.Grade.Should().Be("A");
    }
}
