using CodeSentinel.Application.Abstractions;
using CodeSentinel.Infrastructure.Git;
using LibGit2Sharp;
using Microsoft.Extensions.Logging.Abstractions;

namespace CodeSentinel.Infrastructure.Tests.Git;

// Integration tests for GitRepositoryCloner.
// Uses a real local Git repository as the "remote" to avoid network dependencies.
public class GitRepositoryClonerTests : IDisposable
{
    private readonly string _sourceRepoDir;
    private readonly GitRepositoryCloner _cloner;

    public GitRepositoryClonerTests()
    {
        _sourceRepoDir = Directory.CreateTempSubdirectory("cs-git-source-").FullName;
        InitializeSourceRepoWithCommit(_sourceRepoDir);
        _cloner = new GitRepositoryCloner(NullLogger<GitRepositoryCloner>.Instance);
    }

    [Fact]
    public async Task CloneAsync_ClonesContentIntoTempDirectory()
    {
        await using var cloned = await _cloner.CloneAsync(_sourceRepoDir, CancellationToken.None);

        cloned.LocalPath.Should().NotBeNullOrEmpty();
        Directory.Exists(cloned.LocalPath).Should().BeTrue();
        File.Exists(Path.Combine(cloned.LocalPath, "README.md")).Should().BeTrue();
        File.ReadAllText(Path.Combine(cloned.LocalPath, "README.md")).Should().Contain("Hello");
    }

    [Fact]
    public async Task CloneAsync_ReturnsAbsolutePath()
    {
        await using var cloned = await _cloner.CloneAsync(_sourceRepoDir, CancellationToken.None);

        Path.IsPathRooted(cloned.LocalPath).Should().BeTrue();
    }

    [Fact]
    public async Task ClonedRepository_DisposalRemovesTempDirectory()
    {
        var cloned = await _cloner.CloneAsync(_sourceRepoDir, CancellationToken.None);
        var localPath = cloned.LocalPath;

        await cloned.DisposeAsync();

        Directory.Exists(localPath).Should().BeFalse();
    }

    [Fact]
    public async Task ClonedRepository_DoubleDisposalIsSafe()
    {
        var cloned = await _cloner.CloneAsync(_sourceRepoDir, CancellationToken.None);

        await cloned.DisposeAsync();
        var act = async () => await cloned.DisposeAsync();

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task CloneAsync_OnInvalidSource_PropagatesException()
    {
        // Using a non-existent local path avoids depending on DNS or network state.
        var act = async () => await _cloner.CloneAsync(
            "/path/that/does/not/exist/codesentinel-fake-source",
            CancellationToken.None);

        await act.Should().ThrowAsync<LibGit2SharpException>();
    }

    public void Dispose()
    {
        ClonedGitRepository.TryDeleteDirectory(_sourceRepoDir, NullLogger<GitRepositoryClonerTests>.Instance);
        GC.SuppressFinalize(this);
    }

    private static void InitializeSourceRepoWithCommit(string path)
    {
        Repository.Init(path);
        File.WriteAllText(Path.Combine(path, "README.md"), "# Hello\n");

        using var repo = new Repository(path);
        Commands.Stage(repo, "README.md");
        var signature = new Signature("CodeSentinel Tests", "tests@codesentinel.local", DateTimeOffset.UtcNow);
        repo.Commit("Initial commit", signature, signature);
    }
}
