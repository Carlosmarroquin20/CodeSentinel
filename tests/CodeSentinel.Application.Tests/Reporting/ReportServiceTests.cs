using CodeSentinel.Application.Abstractions;
using CodeSentinel.Application.DependencyInjection;
using CodeSentinel.Core.Findings;
using CodeSentinel.Core.Reporting;
using CodeSentinel.Core.Scanning;
using CodeSentinel.Core.Scoring;
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

    [Fact]
    public async Task WriteReportAsync_WhenWriterFails_LeavesNoFileBehind()
    {
        var outputPath = Path.Combine(_tempDir, "report.sarif");
        await using var provider = BuildProviderWithWriter(new FailingReportWriter("sarif"));
        var service = provider.GetRequiredService<IReportService>();

        var act = () => service.WriteReportAsync(BuildReport(), outputPath, "sarif", CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>();
        Directory.GetFiles(_tempDir).Should().BeEmpty();
    }

    [Fact]
    public async Task WriteReportAsync_WhenWriterFails_KeepsThePreviousReport()
    {
        var outputPath = Path.Combine(_tempDir, "report.sarif");
        File.WriteAllText(outputPath, "previous");
        await using var provider = BuildProviderWithWriter(new FailingReportWriter("sarif"));
        var service = provider.GetRequiredService<IReportService>();

        var act = () => service.WriteReportAsync(BuildReport(), outputPath, "sarif", CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>();
        File.ReadAllText(outputPath).Should().Be("previous");
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
        // Infrastructure not added here: ReportService only needs IEnumerable<IReportWriter>,
        // and pulling in the full stack would conflict with the test-controlled writer formats.
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

    // Writes part of a report, then fails, like a serializer error or a cancellation would.
    private sealed class FailingReportWriter(string format) : IReportWriter
    {
        public string Format { get; } = format;

        public async Task WriteAsync(ScanReport report, Stream output, CancellationToken cancellationToken)
        {
            await output.WriteAsync("{ \"partial\": "u8.ToArray(), cancellationToken);
            throw new InvalidOperationException("writer failed");
        }
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
