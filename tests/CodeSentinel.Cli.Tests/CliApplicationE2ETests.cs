using CodeSentinel.Cli;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Cli.Tests;

// End-to-end tests that drive the CLI exactly as users would,
// composing the real Bootstrap-built service provider.
public class CliApplicationE2ETests : IAsyncDisposable
{
    // Concatenated to keep the canonical AWS example key out of the repo as a literal string,
    // which would otherwise trigger upstream secret scanners.
    private const string FakeAwsKey = "AKIA" + "IOSFODNN7EXAMPLE";

    private readonly string _tempDir = Directory.CreateTempSubdirectory("cs-e2e-").FullName;
    private readonly ServiceProvider _provider = Bootstrap.BuildServiceProvider();

    [Fact]
    public async Task RunAsync_OnEmptyDirectory_ReturnsExitSuccess()
    {
        var exit = await CliApplication.RunAsync([_tempDir], _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Fact]
    public async Task RunAsync_OnDirectoryWithFindings_ReturnsExitFindingsAboveThreshold()
    {
        File.WriteAllText(Path.Combine(_tempDir, "config.env"), $"AWS_ACCESS_KEY_ID={FakeAwsKey}");

        var exit = await CliApplication.RunAsync([_tempDir], _provider);

        exit.Should().Be(CliApplication.ExitFindingsAboveThreshold);
    }

    [Fact]
    public async Task RunAsync_WithNonExistentPath_ReturnsExitScanError()
    {
        var missing = Path.Combine(_tempDir, "does-not-exist");

        var exit = await CliApplication.RunAsync([missing], _provider);

        exit.Should().Be(CliApplication.ExitScanError);
    }

    [Fact]
    public async Task RunAsync_WithJsonOutput_WritesValidJsonReport()
    {
        File.WriteAllText(Path.Combine(_tempDir, "config.env"), $"AWS_ACCESS_KEY_ID={FakeAwsKey}");
        var outputPath = Path.Combine(_tempDir, "report.json");

        var exit = await CliApplication.RunAsync(
            [_tempDir, "--format", "json", "--output", outputPath],
            _provider);

        exit.Should().Be(CliApplication.ExitFindingsAboveThreshold);
        File.Exists(outputPath).Should().BeTrue();

        var content = File.ReadAllText(outputPath);
        content.Should().Contain("\"scanner\"");
        content.Should().Contain("\"findings\"");
        content.Should().Contain("CS001");
    }

    [Fact]
    public async Task RunAsync_WithHtmlOutput_WritesValidHtmlReport()
    {
        File.WriteAllText(Path.Combine(_tempDir, "config.env"), $"AWS_ACCESS_KEY_ID={FakeAwsKey}");
        var outputPath = Path.Combine(_tempDir, "report.html");

        var exit = await CliApplication.RunAsync(
            [_tempDir, "--format", "html", "--output", outputPath],
            _provider);

        exit.Should().Be(CliApplication.ExitFindingsAboveThreshold);
        File.Exists(outputPath).Should().BeTrue();

        var content = File.ReadAllText(outputPath);
        content.Should().StartWith("<!DOCTYPE html>");
        content.Should().Contain("CodeSentinel Security Report");
        content.Should().Contain("CS001");
    }

    [Fact]
    public async Task RunAsync_FormatInferredFromJsonExtension()
    {
        File.WriteAllText(Path.Combine(_tempDir, "config.env"), "no findings here");
        var outputPath = Path.Combine(_tempDir, "report.json");

        await CliApplication.RunAsync([_tempDir, "--output", outputPath], _provider);

        var content = File.ReadAllText(outputPath);
        content.Should().StartWith("{");
        content.Should().Contain("\"scanner\"");
    }

    [Fact]
    public async Task RunAsync_FormatInferredFromHtmlExtension()
    {
        File.WriteAllText(Path.Combine(_tempDir, "config.env"), "no findings here");
        var outputPath = Path.Combine(_tempDir, "report.html");

        await CliApplication.RunAsync([_tempDir, "--output", outputPath], _provider);

        var content = File.ReadAllText(outputPath);
        content.Should().StartWith("<!DOCTYPE html>");
    }

    [Fact]
    public async Task RunAsync_WithUnknownExtension_FallsBackToJson()
    {
        File.WriteAllText(Path.Combine(_tempDir, "config.env"), "no findings here");
        var outputPath = Path.Combine(_tempDir, "report.txt");

        await CliApplication.RunAsync([_tempDir, "--output", outputPath], _provider);

        var content = File.ReadAllText(outputPath);
        content.Should().StartWith("{");
    }

    [Fact]
    public async Task RunAsync_WithoutOutputFlag_DoesNotCreateReportFile()
    {
        File.WriteAllText(Path.Combine(_tempDir, "source.txt"), "harmless content");

        await CliApplication.RunAsync([_tempDir], _provider);

        // The directory should contain only the input file we created, no generated reports.
        Directory.GetFiles(_tempDir).Should().HaveCount(1);
        Directory.GetFiles(_tempDir, "*.json").Should().BeEmpty();
        Directory.GetFiles(_tempDir, "*.html").Should().BeEmpty();
    }

    [Fact]
    public async Task RunAsync_WithUnsupportedFormat_ReturnsExitScanError()
    {
        var outputPath = Path.Combine(_tempDir, "report.xml");

        var exit = await CliApplication.RunAsync(
            [_tempDir, "--format", "xml", "--output", outputPath],
            _provider);

        exit.Should().Be(CliApplication.ExitScanError);
        File.Exists(outputPath).Should().BeFalse();
    }

    [Fact]
    public async Task RunAsync_ShortAliasesWork()
    {
        File.WriteAllText(Path.Combine(_tempDir, "config.env"), "no findings here");
        var outputPath = Path.Combine(_tempDir, "report.html");

        await CliApplication.RunAsync([_tempDir, "-f", "html", "-o", outputPath], _provider);

        File.Exists(outputPath).Should().BeTrue();
        File.ReadAllText(outputPath).Should().StartWith("<!DOCTYPE html>");
    }

    [Fact]
    public async Task RunAsync_WritesReportIntoMissingDirectory()
    {
        var nestedOutput = Path.Combine(_tempDir, "reports", "out", "report.json");

        await CliApplication.RunAsync([_tempDir, "--output", nestedOutput], _provider);

        File.Exists(nestedOutput).Should().BeTrue();
    }

    public async ValueTask DisposeAsync()
    {
        await _provider.DisposeAsync();
        Directory.Delete(_tempDir, recursive: true);
        GC.SuppressFinalize(this);
    }
}
