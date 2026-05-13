namespace CodeSentinel.Application.Abstractions;

public interface IRepositoryCloner
{
    /// <summary>
    /// Clones the given remote repository into a temporary directory.
    /// The returned handle owns the temporary directory and removes it on disposal.
    /// </summary>
    Task<IClonedRepository> CloneAsync(string remoteUrl, CancellationToken cancellationToken);
}

public interface IClonedRepository : IAsyncDisposable
{
    /// <summary>
    /// Absolute path to the working directory of the cloned repository.
    /// </summary>
    string LocalPath { get; }
}
