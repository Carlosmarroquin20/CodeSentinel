using CodeSentinel.Cli;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Cli.Tests;

// Tests for the --fail-on severity threshold flag.
// Each fixture is crafted to produce findings of a known, isolated severity
// so the threshold logic can be verified end-to-end through the real pipeline.
public class CliFailOnThresholdTests : IAsyncDisposable
{
    private const string FakeAwsKey = "AKIA" + "IOSFODNN7EXAMPLE";

    private readonly string _tempDir = Directory.CreateTempSubdirectory("cs-failon-").FullName;
    private readonly ServiceProvider _provider = Bootstrap.BuildServiceProvider();

    [Fact]
    public async Task FailOnCritical_WithOnlyMediumFinding_ReturnsExitSuccess()
    {
        WriteMediumFindingFile();

        var exit = await CliApplication.RunAsync([_tempDir, "--fail-on", "Critical"], _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Fact]
    public async Task FailOnCritical_WithCriticalFinding_ReturnsExitFindingsAboveThreshold()
    {
        WriteCriticalFindingFile();

        var exit = await CliApplication.RunAsync([_tempDir, "--fail-on", "Critical"], _provider);

        exit.Should().Be(CliApplication.ExitFindingsAboveThreshold);
    }

    [Fact]
    public async Task FailOnHigh_WithOnlyMediumFinding_ReturnsExitSuccess()
    {
        WriteMediumFindingFile();

        var exit = await CliApplication.RunAsync([_tempDir, "--fail-on", "High"], _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Fact]
    public async Task FailOnMedium_WithMediumFinding_ReturnsExitFindingsAboveThreshold()
    {
        WriteMediumFindingFile();

        var exit = await CliApplication.RunAsync([_tempDir, "--fail-on", "Medium"], _provider);

        exit.Should().Be(CliApplication.ExitFindingsAboveThreshold);
    }

    [Fact]
    public async Task FailOnCritical_WithNoFindings_ReturnsExitSuccess()
    {
        var exit = await CliApplication.RunAsync([_tempDir, "--fail-on", "Critical"], _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Fact]
    public async Task FailOn_IsCaseInsensitive()
    {
        WriteCriticalFindingFile();

        var exit = await CliApplication.RunAsync([_tempDir, "--fail-on", "critical"], _provider);

        exit.Should().Be(CliApplication.ExitFindingsAboveThreshold);
    }

    [Fact]
    public async Task FailOn_InvalidSeverity_DoesNotReturnSuccess()
    {
        var exit = await CliApplication.RunAsync([_tempDir, "--fail-on", "wrong"], _provider);

        exit.Should().NotBe(CliApplication.ExitSuccess);
    }

    [Fact]
    public async Task WithoutFailOn_AnyFindingStillTriggersExitOne()
    {
        // Regression: omitting the flag must preserve the original behavior where
        // any finding regardless of severity causes a non-zero exit.
        WriteMediumFindingFile();

        var exit = await CliApplication.RunAsync([_tempDir], _provider);

        exit.Should().Be(CliApplication.ExitFindingsAboveThreshold);
    }

    [Fact]
    public async Task FailOnCritical_StillWritesReportContainingAllFindings()
    {
        // The threshold must affect exit code only — reports always include every finding.
        WriteMediumFindingFile();
        var reportPath = Path.Combine(_tempDir, "report.json");

        var exit = await CliApplication.RunAsync(
            [_tempDir, "--fail-on", "Critical", "--output", reportPath],
            _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
        File.Exists(reportPath).Should().BeTrue();
        var content = File.ReadAllText(reportPath);
        content.Should().Contain("CS101");
    }

    public async ValueTask DisposeAsync()
    {
        await _provider.DisposeAsync();
        Directory.Delete(_tempDir, recursive: true);
        GC.SuppressFinalize(this);
    }

    // CS101 (Medium) is triggered by MD5/SHA-1 usage; the file produces no other findings.
    private void WriteMediumFindingFile() =>
        File.WriteAllText(Path.Combine(_tempDir, "crypto.cs"), "var hasher = MD5.Create();");

    // CS001 (Critical) is triggered by an AWS access key ID; the file produces no other findings.
    private void WriteCriticalFindingFile() =>
        File.WriteAllText(Path.Combine(_tempDir, "deploy.env"), $"AWS_ACCESS_KEY_ID={FakeAwsKey}");
}
