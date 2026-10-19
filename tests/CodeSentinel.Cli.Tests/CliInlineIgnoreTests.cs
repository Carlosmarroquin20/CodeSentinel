using CodeSentinel.Cli;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Cli.Tests;

// End-to-end tests for "codesentinel:ignore" line comments and --no-inline-ignore.
public class CliInlineIgnoreTests : IAsyncDisposable
{
    private const string FakeAwsKey = "AKIA" + "IOSFODNN7EXAMPLE";

    private readonly string _tempDir = Directory.CreateTempSubdirectory("cs-inline-").FullName;
    private readonly ServiceProvider _provider = Bootstrap.BuildServiceProvider();

    [Theory]
    [InlineData("# codesentinel:ignore")]
    [InlineData("# CodeSentinel:Ignore")]
    [InlineData("# codesentinel:ignore CS001")]
    [InlineData("// codesentinel:ignore CS005, CS001")]
    public async Task MarkerOnTheLine_SuppressesMatchingFindings(string comment)
    {
        WriteConfig($"AWS_ACCESS_KEY_ID={FakeAwsKey} {comment}");

        var exit = await CliApplication.RunAsync([_tempDir], _provider);

        exit.Should().Be(CliApplication.ExitSuccess);
    }

    [Fact]
    public async Task MarkerForOtherRules_KeepsTheFinding()
    {
        WriteConfig($"AWS_ACCESS_KEY_ID={FakeAwsKey} # codesentinel:ignore CS005");

        var exit = await CliApplication.RunAsync([_tempDir], _provider);

        exit.Should().Be(CliApplication.ExitFindingsAboveThreshold);
    }

    [Fact]
    public async Task MarkerOnAnotherLine_DoesNotSuppress()
    {
        WriteConfig("# codesentinel:ignore", $"AWS_ACCESS_KEY_ID={FakeAwsKey}");

        var exit = await CliApplication.RunAsync([_tempDir], _provider);

        exit.Should().Be(CliApplication.ExitFindingsAboveThreshold);
    }

    [Fact]
    public async Task NoInlineIgnore_ReportsSuppressedLines()
    {
        WriteConfig($"AWS_ACCESS_KEY_ID={FakeAwsKey} # codesentinel:ignore");

        var exit = await CliApplication.RunAsync([_tempDir, "--no-inline-ignore"], _provider);

        exit.Should().Be(CliApplication.ExitFindingsAboveThreshold);
    }

    public async ValueTask DisposeAsync()
    {
        await _provider.DisposeAsync();
        Directory.Delete(_tempDir, recursive: true);
        GC.SuppressFinalize(this);
    }

    private void WriteConfig(params string[] lines) =>
        File.WriteAllLines(Path.Combine(_tempDir, "config.env"), lines);
}
