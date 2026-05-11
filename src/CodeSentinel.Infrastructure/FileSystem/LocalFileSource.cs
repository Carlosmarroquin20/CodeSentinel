using System.Runtime.CompilerServices;
using CodeSentinel.Application.Abstractions;
using CodeSentinel.Core.Detection;
using CodeSentinel.Core.Scanning;
using CodeSentinel.Infrastructure.Rules;
using Microsoft.Extensions.Logging;

namespace CodeSentinel.Infrastructure.FileSystem;

internal sealed class LocalFileSource : IFileSource
{
    // Files above this threshold are skipped to avoid memory pressure on large assets.
    private const long MaxFileSizeBytes = 1_048_576; // 1 MB

    private static readonly HashSet<string> IgnoredDirectoryNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git", "node_modules", "bin", "obj", "dist", "build", ".next",
        "vendor", "__pycache__", ".vs", ".idea", "packages", "target",
        ".gradle", ".terraform", "coverage", "TestResults", ".nuget"
    };

    private static readonly HashSet<string> BinaryExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".so", ".dylib", ".pdb", ".zip", ".tar", ".gz",
        ".rar", ".7z", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
        ".pdf", ".docx", ".xlsx", ".ttf", ".woff", ".woff2", ".eot",
        ".mp3", ".mp4", ".avi", ".mov", ".db", ".sqlite", ".lock",
        ".nupkg", ".snupkg", ".bin", ".dat", ".pyc"
    };

    private readonly ILogger<LocalFileSource> _logger;

    public LocalFileSource(ILogger<LocalFileSource> logger)
    {
        _logger = logger;
    }

    public async IAsyncEnumerable<ScannableFile> GetFilesAsync(
        ScanRequest request,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        // Ignore policy is built per-scan from the request's globs so that --exclude
        // and .codesentinelignore patterns can vary between invocations.
        var ignorePolicy = new GlobIgnorePolicy(request.IgnoreGlobs);

        var root = new DirectoryInfo(request.RootPath);
        if (!root.Exists)
        {
            _logger.LogWarning("Scan root does not exist: {Path}", request.RootPath);
            yield break;
        }

        foreach (var file in root.EnumerateFiles("*", SearchOption.AllDirectories))
        {
            if (cancellationToken.IsCancellationRequested)
                yield break;

            if (!IsEligible(file))
                continue;

            var relativePath = Path.GetRelativePath(request.RootPath, file.FullName);

            if (ignorePolicy.ShouldIgnore(relativePath))
                continue;

            ScannableFile? scannableFile = null;
            try
            {
                if (await BinaryFileDetector.IsBinaryAsync(file, cancellationToken).ConfigureAwait(false))
                    continue;

                var lines = await File.ReadAllLinesAsync(file.FullName, cancellationToken).ConfigureAwait(false);
                scannableFile = new ScannableFile(file.FullName, relativePath, lines);
            }
            catch (IOException ex)
            {
                _logger.LogWarning(ex, "Skipping unreadable file: {Path}", relativePath);
            }

            if (scannableFile is not null)
                yield return scannableFile;
        }
    }

    private static bool IsEligible(FileInfo file)
    {
        if (file.Length > MaxFileSizeBytes)
            return false;

        if (BinaryExtensions.Contains(file.Extension))
            return false;

        return !ContainsIgnoredDirectory(file.DirectoryName);
    }

    private static bool ContainsIgnoredDirectory(string? path)
    {
        if (path is null)
            return false;

        foreach (var segment in path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
        {
            if (IgnoredDirectoryNames.Contains(segment))
                return true;
        }

        return false;
    }
}
