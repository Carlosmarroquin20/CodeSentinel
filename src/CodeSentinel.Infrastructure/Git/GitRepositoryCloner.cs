using CodeSentinel.Application.Abstractions;
using CodeSentinel.Application.Security;
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
        // caller is not blocked. libgit2 polls the transfer-progress callback while
        // downloading, and returning false from it aborts the clone, which is how
        // cancellation reaches an in-flight transfer.
        return Task.Run<IClonedRepository>(() =>
        {
            var tempPath = Path.Combine(Path.GetTempPath(), $"codesentinel-clone-{Guid.NewGuid():N}");
            _logger.LogInformation("Cloning {Url} into {Path}", UrlRedaction.RedactUserInfo(remoteUrl), tempPath);

            var options = new CloneOptions();
            options.FetchOptions.OnTransferProgress = _ => !cancellationToken.IsCancellationRequested;

            // Only the current tree is scanned, so history is never needed. A shallow
            // clone transfers a fraction of the objects for repositories with long
            // histories. libgit2's local transport cannot fetch shallowly, so local
            // paths still get a full clone.
            if (!IsLocalSource(remoteUrl))
                options.FetchOptions.Depth = 1;

            try
            {
                Repository.Clone(remoteUrl, tempPath, options);
                cancellationToken.ThrowIfCancellationRequested();
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

    private static bool IsLocalSource(string remoteUrl) =>
        remoteUrl.StartsWith("file://", StringComparison.OrdinalIgnoreCase) || Directory.Exists(remoteUrl);
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
