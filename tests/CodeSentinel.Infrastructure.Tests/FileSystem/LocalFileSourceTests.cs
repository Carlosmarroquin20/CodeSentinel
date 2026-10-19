using System.Text;
using CodeSentinel.Application.Abstractions;
using CodeSentinel.Application.DependencyInjection;
using CodeSentinel.Core.Scanning;
using CodeSentinel.Infrastructure.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Infrastructure.Tests.FileSystem;

public class LocalFileSourceTests : IDisposable
{
    private readonly string _tempDir;
    private readonly IFileSource _source;
    private readonly ServiceProvider _provider;

    public LocalFileSourceTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("cs-fs-test-").FullName;

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCodeSentinelApplication();
        services.AddCodeSentinelInfrastructure();
        _provider = services.BuildServiceProvider();
        _source = _provider.GetRequiredService<IFileSource>();
    }

    [Fact]
    public async Task GetFilesAsync_WithTextFiles_YieldsExpectedCount()
    {
        File.WriteAllText(Path.Combine(_tempDir, "a.py"), "print('hello')");
        File.WriteAllText(Path.Combine(_tempDir, "b.cs"), "class Foo {}");

        var files = await CollectAsync(_source.GetFilesAsync(ScanRequest.ForPath(_tempDir), CancellationToken.None));

        files.Should().HaveCount(2);
    }

    [Fact]
    public async Task GetFilesAsync_SkipsGitDirectory()
    {
        var gitDir = Directory.CreateDirectory(Path.Combine(_tempDir, ".git"));
        File.WriteAllText(Path.Combine(gitDir.FullName, "config"), "[core]");
        File.WriteAllText(Path.Combine(_tempDir, "app.py"), "x = 1");

        var files = await CollectAsync(_source.GetFilesAsync(ScanRequest.ForPath(_tempDir), CancellationToken.None));

        files.Should().HaveCount(1);
        files[0].FileName.Should().Be("app.py");
    }

    [Fact]
    public async Task GetFilesAsync_ScansRootLocatedInsideAnIgnoredDirectoryName()
    {
        var root = Directory.CreateDirectory(Path.Combine(_tempDir, "build", "repo")).FullName;
        File.WriteAllText(Path.Combine(root, "app.py"), "x = 1");
        File.WriteAllText(Path.Combine(Directory.CreateDirectory(Path.Combine(root, "build")).FullName, "out.py"), "y = 2");

        var files = await CollectAsync(_source.GetFilesAsync(ScanRequest.ForPath(root), CancellationToken.None));

        files.Select(f => f.FileName).Should().Equal("app.py");
    }

    [Fact]
    public async Task GetFilesAsync_SkipsNestedIgnoredDirectories()
    {
        var nested = Directory.CreateDirectory(Path.Combine(_tempDir, "web", "node_modules", "lib")).FullName;
        File.WriteAllText(Path.Combine(nested, "index.js"), "module.exports = 1;");
        File.WriteAllText(Path.Combine(_tempDir, "web", "app.js"), "run();");

        var files = await CollectAsync(_source.GetFilesAsync(ScanRequest.ForPath(_tempDir), CancellationToken.None));

        files.Select(f => f.FileName).Should().Equal("app.js");
    }

    [Fact]
    public async Task GetFilesAsync_SkipsFilesWithNullBytesRegardlessOfExtension()
    {
        File.WriteAllBytes(Path.Combine(_tempDir, "blob.txt"), [0x61, 0x00, 0x62]);
        File.WriteAllText(Path.Combine(_tempDir, "notes.txt"), "some text");

        var files = await CollectAsync(_source.GetFilesAsync(ScanRequest.ForPath(_tempDir), CancellationToken.None));

        files.Select(f => f.FileName).Should().Equal("notes.txt");
    }

    [Theory]
    [InlineData("utf-16")]
    [InlineData("utf-16BE")]
    [InlineData("utf-32")]
    public async Task GetFilesAsync_ReadsWideEncodedTextFilesWithByteOrderMark(string encodingName)
    {
        var encoding = Encoding.GetEncoding(encodingName);
        File.WriteAllText(Path.Combine(_tempDir, "settings.ini"), "first\nsecond", encoding);

        var files = await CollectAsync(_source.GetFilesAsync(ScanRequest.ForPath(_tempDir), CancellationToken.None));

        files.Should().ContainSingle().Which.Lines.Should().Equal("first", "second");
    }

    [Fact]
    public async Task GetFilesAsync_WithNonExistentRoot_YieldsNothing()
    {
        var request = ScanRequest.ForPath(Path.Combine(_tempDir, "does-not-exist"));

        var files = await CollectAsync(_source.GetFilesAsync(request, CancellationToken.None));

        files.Should().BeEmpty();
    }

    [Fact]
    public async Task GetFilesAsync_SkipsFilesWithBinaryExtensions()
    {
        File.WriteAllBytes(Path.Combine(_tempDir, "library.dll"), [0x4D, 0x5A, 0x00]); // MZ header
        File.WriteAllText(Path.Combine(_tempDir, "notes.txt"), "some text");

        var files = await CollectAsync(_source.GetFilesAsync(ScanRequest.ForPath(_tempDir), CancellationToken.None));

        files.Should().HaveCount(1);
        files[0].FileName.Should().Be("notes.txt");
    }

    [Fact]
    public async Task GetFilesAsync_DoesNotFollowSymbolicLinks()
    {
        var outside = Directory.CreateTempSubdirectory("cs-fs-outside-").FullName;
        try
        {
            File.WriteAllText(Path.Combine(outside, "credentials"), "aws_secret = 'outside the scan root'");
            File.WriteAllText(Path.Combine(_tempDir, "app.py"), "x = 1");

            if (!TryCreateSymbolicLinks(outside))
                return; // Creating links needs extra privileges on some Windows setups.

            var files = await CollectAsync(_source.GetFilesAsync(ScanRequest.ForPath(_tempDir), CancellationToken.None));

            files.Select(f => f.FileName).Should().Equal("app.py");
        }
        finally
        {
            Directory.Delete(outside, recursive: true);
        }
    }

    private bool TryCreateSymbolicLinks(string outside)
    {
        try
        {
            File.CreateSymbolicLink(Path.Combine(_tempDir, "linked-file"), Path.Combine(outside, "credentials"));
            Directory.CreateSymbolicLink(Path.Combine(_tempDir, "linked-dir"), outside);
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        _provider.Dispose();
        Directory.Delete(_tempDir, recursive: true);
        GC.SuppressFinalize(this);
    }

    private static async Task<List<T>> CollectAsync<T>(IAsyncEnumerable<T> source)
    {
        var result = new List<T>();
        await foreach (var item in source)
            result.Add(item);
        return result;
    }
}
