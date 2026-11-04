using CodeSentinel.Application.Abstractions;
using CodeSentinel.Infrastructure.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Infrastructure.Tests.FileSystem;

public class IgnoreFileReaderTests : IDisposable
{
    private readonly string _tempDir;
    private readonly ServiceProvider _provider;
    private readonly IIgnoreFileReader _reader;

    public IgnoreFileReaderTests()
    {
        _tempDir = Directory.CreateTempSubdirectory("cs-ignore-test-").FullName;

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddCodeSentinelInfrastructure();
        _provider = services.BuildServiceProvider();
        _reader = _provider.GetRequiredService<IIgnoreFileReader>();
    }

    [Fact]
    public void ReadPatterns_WithoutIgnoreFile_ReturnsEmpty()
    {
        _reader.ReadPatterns(_tempDir).Should().BeEmpty();
    }

    [Fact]
    public void ReadPatterns_SkipsCommentsAndBlankLines()
    {
        File.WriteAllText(
            Path.Combine(_tempDir, IIgnoreFileReader.FileName),
            "# third-party code\nvendor/**\n\n   \n  docs/**  \n# **/*.cs\n");

        _reader.ReadPatterns(_tempDir).Should().Equal("vendor/**", "docs/**");
    }

    [Fact]
    public void ReadPatterns_WithOnlyComments_ReturnsEmpty()
    {
        File.WriteAllText(Path.Combine(_tempDir, IIgnoreFileReader.FileName), "# nothing yet\n");

        _reader.ReadPatterns(_tempDir).Should().BeEmpty();
    }

    public void Dispose()
    {
        _provider.Dispose();
        Directory.Delete(_tempDir, recursive: true);
        GC.SuppressFinalize(this);
    }
}
