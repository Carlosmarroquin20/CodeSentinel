using CodeSentinel.Application.Abstractions;
using CodeSentinel.Application.DependencyInjection;
using CodeSentinel.Core.Scanning;
using CodeSentinel.Infrastructure.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Infrastructure.Tests.Integration;

public class ScanOrchestratorIntegrationTests : IAsyncDisposable
{
    private readonly string _tempDir = Directory.CreateTempSubdirectory("cs-int-test-").FullName;

    [Fact]
    public async Task ExecuteAsync_OverFileContainingAwsKey_DetectsCriticalFinding()
    {
        // Canonical AWS example key from official AWS documentation — intentionally not a real credential.
        File.WriteAllText(
            Path.Combine(_tempDir, "deploy.env"),
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");

        await using var provider = BuildServiceProvider();
        var result = await RunScanAsync(provider);

        result.FilesScanned.Should().BeGreaterThan(0);
        result.Findings.Should().Contain(f => f.RuleId == "CS001");
        result.Score.Value.Should().BeLessThan(100);
    }

    [Fact]
    public async Task ExecuteAsync_OverFileContainingPrivateKeyHeader_DetectsCriticalFinding()
    {
        File.WriteAllText(
            Path.Combine(_tempDir, "server.key"),
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n");

        await using var provider = BuildServiceProvider();
        var result = await RunScanAsync(provider);

        result.Findings.Should().Contain(f => f.RuleId == "CS003");
    }

    [Fact]
    public async Task ExecuteAsync_OverFileContainingWeakHash_DetectsMediumFinding()
    {
        File.WriteAllText(
            Path.Combine(_tempDir, "hasher.cs"),
            "using var h = MD5.Create();\n");

        await using var provider = BuildServiceProvider();
        var result = await RunScanAsync(provider);

        result.Findings.Should().Contain(f => f.RuleId == "CS101");
    }

    [Fact]
    public async Task ExecuteAsync_OverCleanDirectory_ReturnsPerfectScore()
    {
        File.WriteAllText(Path.Combine(_tempDir, "readme.txt"), "No secrets here.\n");

        await using var provider = BuildServiceProvider();
        var result = await RunScanAsync(provider);

        result.Findings.Should().NotContain(f =>
            f.RuleId == "CS001" || f.RuleId == "CS002" || f.RuleId == "CS003" || f.RuleId == "CS005");
        result.Score.Value.Should().Be(100);
    }

    public async ValueTask DisposeAsync()
    {
        await Task.Run(() => Directory.Delete(_tempDir, recursive: true));
        GC.SuppressFinalize(this);
    }

    private Task<ScanResult> RunScanAsync(IServiceProvider provider) =>
        provider.GetRequiredService<IScanOrchestrator>()
            .ExecuteAsync(ScanRequest.ForPath(_tempDir), CancellationToken.None);

    private static ServiceProvider BuildServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCodeSentinelApplication();
        services.AddCodeSentinelInfrastructure();
        return services.BuildServiceProvider();
    }
}
