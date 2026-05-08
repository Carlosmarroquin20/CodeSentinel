using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Scanning;

namespace CodeSentinel.Application.Abstractions;

public interface IFileSource
{
    IAsyncEnumerable<ScannableFile> GetFilesAsync(ScanRequest request, CancellationToken cancellationToken);
}
