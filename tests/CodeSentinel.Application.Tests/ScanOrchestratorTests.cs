using CodeSentinel.Application.Abstractions;
using CodeSentinel.Application.DependencyInjection;
using CodeSentinel.Core.Scanning;
using CodeSentinel.Infrastructure.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

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
