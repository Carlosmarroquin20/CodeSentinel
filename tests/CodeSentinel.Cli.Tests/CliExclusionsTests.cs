using CodeSentinel.Cli;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Cli.Tests;

// End-to-end tests for path exclusions: --exclude CLI flag and .codesentinelignore file.
// Tests use "legacy/" as the excluded path because it is NOT in the LocalFileSource
// default-ignored directory list — verifying the exclusion logic actually fires.
public class CliExclusionsTests : IAsyncDisposable
{
    private const string FakeAwsKey = "AKIA" + "IOSFODNN7EXAMPLE";

    private readonly string _tempDir = Directory.CreateTempSubdirectory("cs-excl-").FullName;
    private readonly ServiceProvider _provider = Bootstrap.BuildServiceProvider();

    [Fact]
    public async Task WithoutExclusion_FindingInLegacyDirIsDetected()
    {
        // Sanity check: without --exclude, the leak inside legacy/ is detected and fails the scan.
        var legacyDir = Directory.CreateDirectory(Path.Combine(_tempDir, "legacy"));
        File.WriteAllText(Path.Combine(legacyDir.FullName, "leaks.env"),
            $"AWS_ACCESS_KEY_ID={FakeAwsKey}");

        var exit = await CliApplication.RunAsync([_tempDir], _provider);

        exit.Should().Be(CliApplication.ExitFindingsAboveThreshold);
    }

    [Fact]
    public async Task Exclude_PreventsFindingsInMatchedPaths()
    {
        var legacyDir = Directory.CreateDirectory(Path.Combine(_tempDir, "legacy"));
        File.WriteAllText(Path.Combine(legacyDir.FullName, "leaks.env"),
            $"AWS_ACCESS_KEY_ID={FakeAwsKey}");

        var exit = await CliApplication.RunAsync(
            [_tempDir, "--exclude", "legacy/**"],
            _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Fact]
    public async Task Exclude_DoesNotAffectNonMatchedPaths()
    {
        // A finding outside the excluded path must still trigger exit code 1.
        var srcDir = Directory.CreateDirectory(Path.Combine(_tempDir, "src"));
        File.WriteAllText(Path.Combine(srcDir.FullName, "config.env"),
            $"AWS_ACCESS_KEY_ID={FakeAwsKey}");

        var exit = await CliApplication.RunAsync(
            [_tempDir, "--exclude", "legacy/**"],
            _provider);

        exit.Should().Be(CliApplication.ExitFindingsAboveThreshold);
    }

    [Fact]
    public async Task Exclude_AcceptsMultiplePatterns()
    {
        Directory.CreateDirectory(Path.Combine(_tempDir, "legacy"));
        Directory.CreateDirectory(Path.Combine(_tempDir, "docs"));
        File.WriteAllText(Path.Combine(_tempDir, "legacy", "a.env"), $"AWS_ACCESS_KEY_ID={FakeAwsKey}");
        File.WriteAllText(Path.Combine(_tempDir, "docs",   "b.env"), $"AWS_ACCESS_KEY_ID={FakeAwsKey}");

        var exit = await CliApplication.RunAsync(
            [_tempDir, "--exclude", "legacy/**", "--exclude", "docs/**"],
            _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Fact]
    public async Task CodeSentinelIgnoreFile_ExcludesMatchingPaths()
    {
        File.WriteAllText(
            Path.Combine(_tempDir, ".codesentinelignore"),
            "legacy/**\n");

        Directory.CreateDirectory(Path.Combine(_tempDir, "legacy"));
        File.WriteAllText(Path.Combine(_tempDir, "legacy", "leaks.env"),
            $"AWS_ACCESS_KEY_ID={FakeAwsKey}");

        var exit = await CliApplication.RunAsync([_tempDir], _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Fact]
    public async Task CodeSentinelIgnoreFile_SkipsCommentsAndBlankLines()
    {
        File.WriteAllText(
            Path.Combine(_tempDir, ".codesentinelignore"),
            "# CodeSentinel ignore patterns\n" +
            "\n" +
            "# blank lines above must be skipped\n" +
            "legacy/**\n" +
            "# trailing comment\n");

        Directory.CreateDirectory(Path.Combine(_tempDir, "legacy"));
        File.WriteAllText(Path.Combine(_tempDir, "legacy", "leaks.env"),
            $"AWS_ACCESS_KEY_ID={FakeAwsKey}");

        var exit = await CliApplication.RunAsync([_tempDir], _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Fact]
    public async Task CliExcludeAndIgnoreFile_AreCombined()
    {
        // The ignore file covers legacy/; the CLI flag covers docs/.
        File.WriteAllText(Path.Combine(_tempDir, ".codesentinelignore"), "legacy/**\n");
        Directory.CreateDirectory(Path.Combine(_tempDir, "legacy"));
        Directory.CreateDirectory(Path.Combine(_tempDir, "docs"));
        File.WriteAllText(Path.Combine(_tempDir, "legacy", "a.env"), $"AWS_ACCESS_KEY_ID={FakeAwsKey}");
        File.WriteAllText(Path.Combine(_tempDir, "docs",   "b.env"), $"AWS_ACCESS_KEY_ID={FakeAwsKey}");

        var exit = await CliApplication.RunAsync(
            [_tempDir, "--exclude", "docs/**"],
            _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Fact]
    public async Task CodeSentinelIgnoreFile_AbsentIsNotAnError()
    {
        File.WriteAllText(Path.Combine(_tempDir, "clean.txt"), "harmless");

        var exit = await CliApplication.RunAsync([_tempDir], _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Fact]
    public async Task ShortAlias_DashE_Works()
    {
        Directory.CreateDirectory(Path.Combine(_tempDir, "legacy"));
        File.WriteAllText(Path.Combine(_tempDir, "legacy", "leaks.env"),
            $"AWS_ACCESS_KEY_ID={FakeAwsKey}");

        var exit = await CliApplication.RunAsync(
            [_tempDir, "-e", "legacy/**"],
            _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    public async ValueTask DisposeAsync()
    {
        await _provider.DisposeAsync();
        Directory.Delete(_tempDir, recursive: true);
        GC.SuppressFinalize(this);
    }
}
