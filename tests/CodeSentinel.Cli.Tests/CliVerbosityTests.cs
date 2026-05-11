using CodeSentinel.Cli;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Cli.Tests;

// End-to-end tests for --verbose and --quiet flags.
// Verifies that the parser accepts them on the root command and on subcommands,
// and that the resulting scan still produces correct exit codes.
public class CliVerbosityTests : IAsyncDisposable
{
    private readonly string _tempDir = Directory.CreateTempSubdirectory("cs-verb-").FullName;
    private readonly ServiceProvider _provider = Bootstrap.BuildServiceProvider();

    [Theory]
    [InlineData("--verbose")]
    [InlineData("-v")]
    [InlineData("--quiet")]
    [InlineData("-q")]
    public async Task ScanCommand_AcceptsVerbosityFlag_WithoutParserError(string flag)
    {
        var exit = await CliApplication.RunAsync([_tempDir, flag], _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Theory]
    [InlineData("--verbose")]
    [InlineData("-v")]
    [InlineData("--quiet")]
    [InlineData("-q")]
    public async Task ListRulesSubcommand_AcceptsVerbosityFlag(string flag)
    {
        // The global option must be accepted on subcommands too.
        var original = Console.Out;
        try
        {
            using var captured = new StringWriter();
            Console.SetOut(captured);

            var exit = await CliApplication.RunAsync(["list-rules", flag], _provider);

            exit.Should().Be(CliApplication.ExitSuccess);
        }
        finally
        {
            Console.SetOut(original);
        }
    }

    [Fact]
    public async Task BothFlagsTogether_AreAcceptedByParser()
    {
        // Behavior with both flags: --verbose wins at the Bootstrap level.
        // Here we just verify the parser does not reject the combination.
        var exit = await CliApplication.RunAsync([_tempDir, "--verbose", "--quiet"], _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    public async ValueTask DisposeAsync()
    {
        await _provider.DisposeAsync();
        Directory.Delete(_tempDir, recursive: true);
        GC.SuppressFinalize(this);
    }
}
