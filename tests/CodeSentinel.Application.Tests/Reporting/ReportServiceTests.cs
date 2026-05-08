using CodeSentinel.Application.Abstractions;
using CodeSentinel.Application.DependencyInjection;
using CodeSentinel.Core.Findings;
using CodeSentinel.Core.Reporting;
using CodeSentinel.Core.Scanning;
using CodeSentinel.Core.Scoring;
using CodeSentinel.Infrastructure.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Application.Tests.Reporting;

public class ReportServiceTests : IDisposable
{
    private readonly string _tempDir = Directory.CreateTempSubdirectory("cs-report-test-").FullName;

    [Fact]
    public async Task WriteReportAsync_WithRegisteredFormat_CallsCorrectWriter()
    {
        var writer = new SpyReportWriter("json");
        await using var provider = BuildProviderWithWriter(writer);
        var service = provider.GetRequiredService<IReportService>();

        await service.WriteReportAsync(
            BuildReport(),
            Path.Combine(_tempDir, "report.json"),
            format: "json",
            CancellationToken.None);

        writer.WasCalled.Should().BeTrue();
    }

    [Fact]
    public async Task WriteReportAsync_IsCaseInsensitiveOnFormat()
    {
        var writer = new SpyReportWriter("json");
        await using var provider = BuildProviderWithWriter(writer);
        var service = provider.GetRequiredService<IReportService>();

        await service.WriteReportAsync(
            BuildReport(),
            Path.Combine(_tempDir, "report.json"),
            format: "JSON",
            CancellationToken.None);

        writer.WasCalled.Should().BeTrue();
    }

    [Fact]
    public async Task WriteReportAsync_CreatesOutputFile()
    {
        var outputPath = Path.Combine(_tempDir, "report.json");
        var writer = new SpyReportWriter("json");
        await using var provider = BuildProviderWithWriter(writer);
        var service = provider.GetRequiredService<IReportService>();

        await service.WriteReportAsync(BuildReport(), outputPath, "json", CancellationToken.None);

        File.Exists(outputPath).Should().BeTrue();
    }

    [Fact]
    public async Task WriteReportAsync_CreatesOutputDirectoryIfMissing()
    {
        var outputPath = Path.Combine(_tempDir, "nested", "dir", "report.json");
        var writer = new SpyReportWriter("json");
        await using var provider = BuildProviderWithWriter(writer);
        var service = provider.GetRequiredService<IReportService>();

        await service.WriteReportAsync(BuildReport(), outputPath, "json", CancellationToken.None);

        File.Exists(outputPath).Should().BeTrue();
    }

    [Fact]
    public async Task WriteReportAsync_WithUnknownFormat_ThrowsNotSupportedException()
    {
        var writer = new SpyReportWriter("json");
        await using var provider = BuildProviderWithWriter(writer);
        var service = provider.GetRequiredService<IReportService>();

        var act = async () => await service.WriteReportAsync(
            BuildReport(),
            Path.Combine(_tempDir, "report.xml"),
            format: "xml",
            CancellationToken.None);

        await act.Should().ThrowAsync<NotSupportedException>()
            .WithMessage("*xml*");
    }

    [Fact]
    public void SupportedFormats_ReflectsRegisteredWriters()
    {
        var writer = new SpyReportWriter("json");
        using var provider = BuildProviderWithWriter(writer);
        var service = provider.GetRequiredService<IReportService>();

        service.SupportedFormats.Should().Contain("json");
    }

    public void Dispose()
    {
        Directory.Delete(_tempDir, recursive: true);
        GC.SuppressFinalize(this);
    }

    private static ServiceProvider BuildProviderWithWriter(IReportWriter writer)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCodeSentinelApplication();
        services.AddCodeSentinelInfrastructure();
        services.AddSingleton(writer);
        return services.BuildServiceProvider();
    }

    private static ScanReport BuildReport()
    {
        var score = SecurityScore.Perfect;
        var result = ScanResult.Empty(score);
        return new ScanReport(
            TargetPath: "/repo",
            ScannedAt: DateTimeOffset.UtcNow,
            ScannerVersion: "0.1.0",
            Result: result);
    }

    // Concrete test double — records whether WriteAsync was invoked.
    private sealed class SpyReportWriter : IReportWriter
    {
        public SpyReportWriter(string format) => Format = format;

        public string Format { get; }
        public bool WasCalled { get; private set; }

        public Task WriteAsync(ScanReport report, Stream output, CancellationToken cancellationToken)
        {
            WasCalled = true;
            return Task.CompletedTask;
        }
    }
}
