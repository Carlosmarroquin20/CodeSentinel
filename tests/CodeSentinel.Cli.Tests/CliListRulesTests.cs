using CodeSentinel.Cli;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Cli.Tests;

// End-to-end tests for the list-rules subcommand.
// Uses Console.SetOut to capture stdout; xUnit runs tests within a class sequentially
// by default, so there is no race on the global Console writer.
public class CliListRulesTests : IAsyncDisposable
{
    private readonly ServiceProvider _provider = Bootstrap.BuildServiceProvider();

    [Fact]
    public async Task ListRules_ReturnsExitSuccess()
    {
        var (exit, _) = await RunCapturedAsync("list-rules");

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Fact]
    public async Task ListRules_PrintsHeaderColumns()
    {
        var (_, stdout) = await RunCapturedAsync("list-rules");

        stdout.Should().Contain("ID");
        stdout.Should().Contain("SEVERITY");
        stdout.Should().Contain("CATEGORY");
        stdout.Should().Contain("TITLE");
    }

    [Fact]
    public async Task ListRules_IncludesEveryBuiltInRule()
    {
        var (_, stdout) = await RunCapturedAsync("list-rules");

        stdout.Should().Contain("CS001");  // AWS Access Key
        stdout.Should().Contain("CS002");  // AWS Secret Key
        stdout.Should().Contain("CS003");  // Private Key
        stdout.Should().Contain("CS004");  // JWT
        stdout.Should().Contain("CS005");  // Hardcoded Credential
        stdout.Should().Contain("CS101");  // Weak Hash
        stdout.Should().Contain("CS900");  // High-Entropy String
    }

    [Fact]
    public async Task ListRules_IncludesRuleTitles()
    {
        var (_, stdout) = await RunCapturedAsync("list-rules");

        stdout.Should().Contain("AWS Access Key ID");
        stdout.Should().Contain("Private Key");
        stdout.Should().Contain("Weak Hash Algorithm");
        stdout.Should().Contain("High-Entropy String");
    }

    [Fact]
    public async Task ListRules_IncludesSeveritiesAndCategories()
    {
        var (_, stdout) = await RunCapturedAsync("list-rules");

        stdout.Should().Contain("Critical");
        stdout.Should().Contain("High");
        stdout.Should().Contain("Medium");
        stdout.Should().Contain("Secret");
        stdout.Should().Contain("InsecurePattern");
    }

    [Fact]
    public async Task ListRules_OutputsSortedByRuleIdAscending()
    {
        var (_, stdout) = await RunCapturedAsync("list-rules");

        var i001 = stdout.IndexOf("CS001", StringComparison.Ordinal);
        var i005 = stdout.IndexOf("CS005", StringComparison.Ordinal);
        var i101 = stdout.IndexOf("CS101", StringComparison.Ordinal);
        var i900 = stdout.IndexOf("CS900", StringComparison.Ordinal);

        i001.Should().BeLessThan(i005);
        i005.Should().BeLessThan(i101);
        i101.Should().BeLessThan(i900);
    }

    [Fact]
    public async Task ListRules_DoesNotRequirePathArgument()
    {
        // No path is passed; the subcommand must still succeed without errors.
        var (exit, _) = await RunCapturedAsync("list-rules");

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Fact]
    public async Task ScanCommand_StillWorksWhenListRulesIsRegistered()
    {
        // Regression: adding a subcommand must not break the default scan invocation.
        var tempDir = Directory.CreateTempSubdirectory("cs-list-regression-").FullName;
        try
        {
            var exit = await CliApplication.RunAsync([tempDir], _provider);
            exit.Should().Be(CliApplication.ExitSuccess);
        }
        finally
        {
            Directory.Delete(tempDir, recursive: true);
        }
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
