using CodeSentinel.Cli;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Cli.Tests;

// Invalid command lines must exit with 2, not 1. Exit code 1 is reserved for "findings at
// or above the threshold", and a pipeline has to be able to tell a typo in its own
// configuration from a repository with problems.
public class CliArgumentErrorTests : IAsyncDisposable
{
    private readonly ServiceProvider _provider = Bootstrap.BuildServiceProvider();
    private readonly string _tempDir = Directory.CreateTempSubdirectory("cs-cli-args-").FullName;

    [Fact]
    public async Task MissingTarget_ReturnsExitScanError()
    {
        var (exit, stderr) = await RunCapturedAsync();

        exit.Should().Be(CliApplication.ExitScanError);
        stderr.Should().Contain("Required argument missing");
    }

    [Fact]
    public async Task UnknownOption_ReturnsExitScanErrorAndNamesTheOption()
    {
        var (exit, stderr) = await RunCapturedAsync(_tempDir, "--bogus");

        exit.Should().Be(CliApplication.ExitScanError);
        stderr.Should().Contain("--bogus");
    }

    [Fact]
    public async Task InvalidOptionValue_ReturnsExitScanError()
    {
        var (exit, stderr) = await RunCapturedAsync(_tempDir, "--fail-on", "Severe");

        exit.Should().Be(CliApplication.ExitScanError);
        stderr.Should().Contain("Severe");
    }

    [Fact]
    public async Task OptionWithoutValue_ReturnsExitScanError()
    {
        var (exit, _) = await RunCapturedAsync(_tempDir, "--output");

        exit.Should().Be(CliApplication.ExitScanError);
    }

    [Fact]
    public async Task UnknownOptionOnSubcommand_ReturnsExitScanError()
    {
        var (exit, _) = await RunCapturedAsync("list-rules", "--bogus");

        exit.Should().Be(CliApplication.ExitScanError);
    }

    [Fact]
    public async Task ValidArguments_AreNotAffected()
    {
        var (exit, stderr) = await RunCapturedAsync(_tempDir, "--fail-on", "High");

        exit.Should().Be(CliApplication.ExitSuccess);
        stderr.Should().BeEmpty();
    }

    // Parse errors are written to stderr; the help text that follows them goes to stdout.
    private async Task<(int ExitCode, string Stderr)> RunCapturedAsync(params string[] args)
    {
        var originalOut = Console.Out;
        var originalError = Console.Error;
        try
        {
            using var capturedOut = new StringWriter();
            using var capturedError = new StringWriter();
            Console.SetOut(capturedOut);
            Console.SetError(capturedError);

            var exit = await CliApplication.RunAsync(args, _provider);
            return (exit, capturedError.ToString());
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalError);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _provider.DisposeAsync();
        Directory.Delete(_tempDir, recursive: true);
        GC.SuppressFinalize(this);
    }
}
