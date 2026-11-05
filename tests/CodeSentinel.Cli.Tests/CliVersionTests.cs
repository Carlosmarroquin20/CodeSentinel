using CodeSentinel.Cli;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Cli.Tests;

// Tests for --version and --help, which short-circuit before the target argument is
// validated. System.CommandLine 2.0 reads Console.Out when each invocation starts, so
// the output can be captured with Console.SetOut; test parallelization is disabled for
// this assembly (see AssemblyInfo.cs).
public class CliVersionTests : IAsyncDisposable
{
    private readonly ServiceProvider _provider = Bootstrap.BuildServiceProvider();

    [Fact]
    public async Task VersionFlag_ExitsZeroAndDoesNotRequireTarget()
    {
        var (exit, _) = await RunCapturedAsync("--version");

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    // System.CommandLine prints the entry assembly's version. Inside the test run that is
    // the test host, not codesentinel, so only the shape of the output is checked here.
    [Fact]
    public async Task VersionFlag_PrintsASingleVersionLine()
    {
        var (_, stdout) = await RunCapturedAsync("--version");

        stdout.Trim().Should().MatchRegex(@"^\d+\.\d+\.\d+\S*$");
    }

    [Fact]
    public async Task HelpFlag_ExitsZeroAndDoesNotRequireTarget()
    {
        var (exit, _) = await RunCapturedAsync("--help");

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Theory]
    [InlineData("-h")]
    [InlineData("-?")]
    public async Task HelpShortAliases_AlsoWork(string alias)
    {
        var (exit, stdout) = await RunCapturedAsync(alias);

        exit.Should().Be(CliApplication.ExitSuccess);
        stdout.Should().Contain("Usage:");
    }

    [Fact]
    public async Task HelpFlag_ListsTargetOptionsAndSubcommand()
    {
        var (_, stdout) = await RunCapturedAsync("--help");

        stdout.Should().Contain("CodeSentinel - security scanner for source repositories.");
        stdout.Should().Contain("<target>");
        stdout.Should().Contain("-f, --format");
        stdout.Should().Contain("-o, --output");
        stdout.Should().Contain("--fail-on");
        stdout.Should().Contain("-e, --exclude");
        stdout.Should().Contain("--no-ignore-file");
        stdout.Should().Contain("--no-inline-ignore");
        stdout.Should().Contain("-v, --verbose");
        stdout.Should().Contain("-q, --quiet");
        stdout.Should().Contain("--version");
        stdout.Should().Contain("list-rules");
    }

    [Fact]
    public async Task SubcommandHelp_IncludesTheRecursiveVerbosityOptions()
    {
        var (exit, stdout) = await RunCapturedAsync("list-rules", "--help");

        exit.Should().Be(CliApplication.ExitSuccess);
        stdout.Should().Contain("List all detection rules registered in the scanner.");
        stdout.Should().Contain("-v, --verbose");
        stdout.Should().Contain("-q, --quiet");
    }

    private async Task<(int ExitCode, string Stdout)> RunCapturedAsync(params string[] args)
    {
        var original = Console.Out;
        try
        {
            using var captured = new StringWriter();
            Console.SetOut(captured);

            var exit = await CliApplication.RunAsync(args, _provider);
            return (exit, captured.ToString());
        }
        finally
        {
            Console.SetOut(original);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _provider.DisposeAsync();
        GC.SuppressFinalize(this);
    }
}
