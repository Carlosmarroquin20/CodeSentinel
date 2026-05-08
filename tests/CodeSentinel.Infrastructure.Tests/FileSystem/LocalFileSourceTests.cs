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
