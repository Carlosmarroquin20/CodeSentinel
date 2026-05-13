using CodeSentinel.Cli;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Cli.Tests;

// Tests for --version and --help short-circuit behavior introduced by UseDefaults.
// Stdout content is not asserted here: System.CommandLine's SystemConsole caches
// Console.Out at parser-build time, so Console.SetOut redirects from inside the
// test process are not observed. The actual rendered text is exercised via
// integration runs (and verified manually during development).
public class CliVersionTests : IAsyncDisposable
{
    private readonly ServiceProvider _provider = Bootstrap.BuildServiceProvider();

    [Fact]
    public async Task VersionFlag_ExitsZeroAndDoesNotRequireTarget()
    {
        // --version short-circuits before the parser validates the target argument.
        var exit = await CliApplication.RunAsync(["--version"], _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Fact]
    public async Task HelpFlag_ExitsZeroAndDoesNotRequireTarget()
    {
        var exit = await CliApplication.RunAsync(["--help"], _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Theory]
    [InlineData("-h")]
    [InlineData("-?")]
    public async Task HelpShortAliases_AlsoWork(string alias)
    {
        var exit = await CliApplication.RunAsync([alias], _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    public async ValueTask DisposeAsync()
    {
        await _provider.DisposeAsync();
        GC.SuppressFinalize(this);
    }
}
