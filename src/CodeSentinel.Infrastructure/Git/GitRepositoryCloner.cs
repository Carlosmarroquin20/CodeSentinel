using CodeSentinel.Application.Abstractions;
using LibGit2Sharp;
using Microsoft.Extensions.Logging;

namespace CodeSentinel.Infrastructure.Git;

internal sealed class GitRepositoryCloner : IRepositoryCloner
{
    private readonly ILogger<GitRepositoryCloner> _logger;

    public GitRepositoryCloner(ILogger<GitRepositoryCloner> logger)
    {
        _logger = logger;
    }

    public Task<IClonedRepository> CloneAsync(string remoteUrl, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(remoteUrl);

        // LibGit2Sharp's Clone is synchronous; run it on a worker thread so the
        // caller is not blocked. Cancellation cannot be honoured mid-clone (libgit2
        // does not expose an idiomatic cancel hook), but the wrapping Task still
        // becomes faulted when the token fires.
        return Task.Run<IClonedRepository>(() =>
        {
            var tempPath = Path.Combine(Path.GetTempPath(), $"codesentinel-clone-{Guid.NewGuid():N}");
            _logger.LogInformation("Cloning {Url} into {Path}", remoteUrl, tempPath);

            try
            {
                Repository.Clone(remoteUrl, tempPath);
            }
            catch
            {
                // Roll back any partial checkout if Clone threw mid-way.
                ClonedGitRepository.TryDeleteDirectory(tempPath, _logger);
                throw;
            }

            return new ClonedGitRepository(tempPath, _logger);
        }, cancellationToken);
    }
}

internal sealed class ClonedGitRepository : IClonedRepository
{
    private readonly ILogger _logger;
    private bool _disposed;

    public ClonedGitRepository(string localPath, ILogger logger)
    {
        LocalPath = localPath;
        _logger = logger;
    }

    public string LocalPath { get; }

    public ValueTask DisposeAsync()
    {
        if (_disposed)
            return ValueTask.CompletedTask;

        _disposed = true;
        TryDeleteDirectory(LocalPath, _logger);
        return ValueTask.CompletedTask;
    }

    // Git creates files inside .git/ that are marked read-only on Windows
    // (pack-*.idx, etc.). A naive Directory.Delete throws UnauthorizedAccessException
    // on those, so we clear the read-only flag first and ignore stragglers.
    public static void TryDeleteDirectory(string path, ILogger logger)
    {
        if (!Directory.Exists(path))
            return;

        try
        {
            foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                try
                {
                    File.SetAttributes(file, FileAttributes.Normal);
                }
                catch
                {
                    // best-effort attribute reset
                }
            }
            Directory.Delete(path, recursive: true);
            logger.LogDebug("Removed cloned repository at {Path}", path);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not fully clean up cloned repository at {Path}", path);
        }
    }
}
