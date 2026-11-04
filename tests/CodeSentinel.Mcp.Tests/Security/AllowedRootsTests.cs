using CodeSentinel.Mcp.Security;

namespace CodeSentinel.Mcp.Tests.Security;

public sealed class AllowedRootsTests : IDisposable
{
    private readonly string _first = Directory.CreateTempSubdirectory("cs-mcp-root-a-").FullName;
    private readonly string _second = Directory.CreateTempSubdirectory("cs-mcp-root-b-").FullName;

    [Fact]
    public void Parse_WithoutConfiguration_UsesWorkingDirectory()
    {
        var roots = AllowedRoots.Parse([], environmentValue: null, workingDirectory: _first);

        roots.Paths.Should().Equal(AllowedRoots.Normalize(_first));
    }

    [Fact]
    public void Parse_WithRepeatedArgument_ReturnsEveryRoot()
    {
        var roots = AllowedRoots.Parse(
            ["--allowed-root", _first, $"--allowed-root={_second}"],
            environmentValue: null,
            workingDirectory: _first);

        roots.Paths.Should().Equal(AllowedRoots.Normalize(_first), AllowedRoots.Normalize(_second));
    }

    [Fact]
    public void Parse_WithEnvironmentVariable_SplitsOnPathSeparator()
    {
        var roots = AllowedRoots.Parse(
            [],
            environmentValue: _first + Path.PathSeparator + _second,
            workingDirectory: Path.GetTempPath());

        roots.Paths.Should().Equal(AllowedRoots.Normalize(_first), AllowedRoots.Normalize(_second));
    }

    [Fact]
    public void Parse_CommandLineTakesPrecedenceOverEnvironment()
    {
        var roots = AllowedRoots.Parse(
            ["--allowed-root", _first],
            environmentValue: _second,
            workingDirectory: _second);

        roots.Paths.Should().Equal(AllowedRoots.Normalize(_first));
    }

    [Fact]
    public void Parse_RemovesTrailingSeparatorsAndDuplicates()
    {
        var roots = AllowedRoots.Parse(
            ["--allowed-root", _first + Path.DirectorySeparatorChar, "--allowed-root", _first],
            environmentValue: null,
            workingDirectory: _first);

        roots.Paths.Should().Equal(AllowedRoots.Normalize(_first));
    }

    [Fact]
    public void Parse_WithMissingDirectory_Throws()
    {
        var missing = Path.Combine(_first, "missing");

        var act = () => AllowedRoots.Parse(
            ["--allowed-root", missing],
            environmentValue: null,
            workingDirectory: _first);

        act.Should().Throw<ArgumentException>().WithMessage("*does not exist*");
    }

    [Fact]
    public void Parse_WithRelativeRoot_Throws()
    {
        var act = () => AllowedRoots.Parse(["--allowed-root", "src"], environmentValue: null, workingDirectory: _first);

        act.Should().Throw<ArgumentException>().WithMessage("*absolute*");
    }

    [Fact]
    public void Parse_WithoutValue_Throws()
    {
        var act = () => AllowedRoots.Parse(["--allowed-root"], environmentValue: null, workingDirectory: _first);

        act.Should().Throw<ArgumentException>().WithMessage("*requires a directory path*");
    }

    [Fact]
    public void Parse_WithUnknownArgument_Throws()
    {
        var act = () => AllowedRoots.Parse(["--verbose"], environmentValue: null, workingDirectory: _first);

        act.Should().Throw<ArgumentException>().WithMessage("Unknown argument: --verbose*");
    }

    [Fact]
    public void FindContainingRoot_DoesNotMatchSiblingWithSamePrefix()
    {
        var roots = AllowedRoots.Parse(["--allowed-root", _first], environmentValue: null, workingDirectory: _first);
        var root = roots.Paths[0];

        roots.FindContainingRoot(root).Should().Be(root);
        roots.FindContainingRoot(Path.Combine(root, "src")).Should().Be(root);
        roots.FindContainingRoot(root + "-backup").Should().BeNull();
    }

    public void Dispose()
    {
        Directory.Delete(_first, recursive: true);
        Directory.Delete(_second, recursive: true);
    }
}
