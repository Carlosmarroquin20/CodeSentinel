using CodeSentinel.Mcp.Security;
using ModelContextProtocol;

namespace CodeSentinel.Mcp.Tests.Security;

// Layout used by every test:
//   <temp>/root/            allowed root
//   <temp>/root/repo/       a repository inside it
//   <temp>/root-backup/     sibling whose name starts with the root's name
//   <temp>/outside/         a directory the agent must not reach
public sealed class ScanPathValidatorTests : IDisposable
{
    private readonly string _temp;
    private readonly string _root;
    private readonly string _repo;
    private readonly string _sibling;
    private readonly string _outside;
    private readonly ScanPathValidator _validator;

    public ScanPathValidatorTests()
    {
        _temp = Directory.CreateTempSubdirectory("cs-mcp-paths-").FullName;
        _root = Directory.CreateDirectory(Path.Combine(_temp, "root")).FullName;
        _repo = Directory.CreateDirectory(Path.Combine(_root, "repo")).FullName;
        _sibling = Directory.CreateDirectory(Path.Combine(_temp, "root-backup")).FullName;
        _outside = Directory.CreateDirectory(Path.Combine(_temp, "outside")).FullName;

        var roots = AllowedRoots.Parse(["--allowed-root", _root], environmentValue: null, workingDirectory: _root);
        _validator = new ScanPathValidator(roots);
    }

    [Fact]
    public void Resolve_RelativePathInsideRoot_ReturnsFullPath()
    {
        _validator.Resolve("repo").Should().Be(_repo);
    }

    [Fact]
    public void Resolve_AbsolutePathInsideRoot_ReturnsNormalizedPath()
    {
        _validator.Resolve(_repo + Path.DirectorySeparatorChar).Should().Be(_repo);
    }

    [Fact]
    public void Resolve_CurrentDirectory_ReturnsRoot()
    {
        _validator.Resolve(".").Should().Be(_root);
    }

    [Fact]
    public void Resolve_DotDotThatStaysInside_IsAccepted()
    {
        _validator.Resolve(Path.Combine("repo", "..", "repo")).Should().Be(_repo);
    }

    [Fact]
    public void Resolve_DotDotEscapingTheRoot_IsRejected()
    {
        var act = () => _validator.Resolve(Path.Combine("..", "outside"));

        act.Should().Throw<McpException>().WithMessage("*outside the allowed roots*");
    }

    [Fact]
    public void Resolve_AbsolutePathOutsideRoot_IsRejected()
    {
        var act = () => _validator.Resolve(_outside);

        act.Should().Throw<McpException>().WithMessage("*outside the allowed roots*");
    }

    [Fact]
    public void Resolve_SiblingSharingTheRootPrefix_IsRejected()
    {
        var act = () => _validator.Resolve(_sibling);

        act.Should().Throw<McpException>().WithMessage("*outside the allowed roots*");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Resolve_EmptyPath_IsRejected(string? path)
    {
        var act = () => _validator.Resolve(path);

        act.Should().Throw<McpException>().WithMessage("A path is required.*");
    }

    [Theory]
    [InlineData("https://github.com/octocat/Hello-World.git")]
    [InlineData("ssh://git@github.com/owner/repo.git")]
    [InlineData("git@github.com:owner/repo.git")]
    [InlineData("file:///etc")]
    public void Resolve_RemoteOrUrlTarget_IsRejected(string path)
    {
        var act = () => _validator.Resolve(path);

        act.Should().Throw<McpException>().WithMessage("Remote repositories are not supported*");
    }

    [Theory]
    [InlineData(@"\\server\share\repo")]
    [InlineData(@"\\?\C:\Windows")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData("//server/share/repo")]
    public void Resolve_UncOrDevicePath_IsRejected(string path)
    {
        var act = () => _validator.Resolve(path);

        act.Should().Throw<McpException>().WithMessage("UNC and device paths are not allowed.*");
    }

    [Fact]
    public void Resolve_PathWithNullCharacter_IsRejected()
    {
        var act = () => _validator.Resolve("repo\0/../..");

        act.Should().Throw<McpException>().WithMessage("*null character*");
    }

    [Fact]
    public void Resolve_MissingDirectory_IsRejected()
    {
        var act = () => _validator.Resolve("missing");

        act.Should().Throw<McpException>().WithMessage("*does not exist*");
    }

    [Fact]
    public void Resolve_File_IsRejected()
    {
        File.WriteAllText(Path.Combine(_repo, "app.py"), "print('hi')");

        var act = () => _validator.Resolve(Path.Combine("repo", "app.py"));

        act.Should().Throw<McpException>().WithMessage("*is a file*");
    }

    [Fact]
    public void Resolve_LinkInsideRootPointingOutside_IsRejected()
    {
        var link = Path.Combine(_root, "escape");
        DirectoryLinks.Create(link, _outside);

        var act = () => _validator.Resolve("escape");

        act.Should().Throw<McpException>().WithMessage("*symbolic link or junction*");
    }

    [Fact]
    public void Resolve_DirectoryBelowALink_IsRejected()
    {
        Directory.CreateDirectory(Path.Combine(_outside, "nested"));
        DirectoryLinks.Create(Path.Combine(_root, "escape"), _outside);

        var act = () => _validator.Resolve(Path.Combine("escape", "nested"));

        act.Should().Throw<McpException>().WithMessage("*symbolic link or junction*");
    }

    [Fact]
    public void Rejection_ListsTheAllowedRoots()
    {
        var act = () => _validator.Resolve(_outside);

        act.Should().Throw<McpException>().WithMessage($"*Allowed roots: {_root}");
    }

    public void Dispose()
    {
        // Remove links first so the recursive delete cannot reach their targets.
        foreach (var dir in Directory.EnumerateDirectories(_root))
        {
            if (new DirectoryInfo(dir).Attributes.HasFlag(FileAttributes.ReparsePoint))
                Directory.Delete(dir);
        }

        Directory.Delete(_temp, recursive: true);
    }
}
