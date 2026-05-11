using CodeSentinel.Cli;
using Microsoft.Extensions.Logging;

namespace CodeSentinel.Cli.Tests;

public class BootstrapLogLevelTests
{
    [Fact]
    public void ResolveLogLevel_WithNoFlags_ReturnsInformation()
    {
        Bootstrap.ResolveLogLevel(["/some/path"]).Should().Be(LogLevel.Information);
    }

    [Fact]
    public void ResolveLogLevel_WithEmptyArgs_ReturnsInformation()
    {
        Bootstrap.ResolveLogLevel([]).Should().Be(LogLevel.Information);
    }

    [Theory]
    [InlineData("--verbose")]
    [InlineData("-v")]
    public void ResolveLogLevel_WithVerbose_ReturnsDebug(string flag)
    {
        Bootstrap.ResolveLogLevel(["/path", flag]).Should().Be(LogLevel.Debug);
    }

    [Theory]
    [InlineData("--quiet")]
    [InlineData("-q")]
    public void ResolveLogLevel_WithQuiet_ReturnsWarning(string flag)
    {
        Bootstrap.ResolveLogLevel(["/path", flag]).Should().Be(LogLevel.Warning);
    }

    [Fact]
    public void ResolveLogLevel_WithBothFlags_VerboseWins()
    {
        Bootstrap.ResolveLogLevel(["/path", "--quiet", "--verbose"]).Should().Be(LogLevel.Debug);
        Bootstrap.ResolveLogLevel(["/path", "-v", "-q"]).Should().Be(LogLevel.Debug);
    }

    [Fact]
    public void ResolveLogLevel_IgnoresUnrelatedArgs()
    {
        // The scan path or other options should not be confused for verbosity flags.
        Bootstrap.ResolveLogLevel(["/path", "--exclude", "vendor/**", "--output", "r.json"])
            .Should().Be(LogLevel.Information);
    }

    [Fact]
    public void ResolveLogLevel_DetectsFlagAmongOtherArgs()
    {
        Bootstrap.ResolveLogLevel(["/path", "--exclude", "x", "-v", "--output", "r.json"])
            .Should().Be(LogLevel.Debug);
    }
}
