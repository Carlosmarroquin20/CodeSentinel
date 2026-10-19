using System.Runtime.CompilerServices;
using System.Text;
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

    // Directories the process cannot open are skipped rather than aborting the walk.
    // Symbolic links and junctions are skipped, never followed. A scanned repository
    // (especially a cloned remote one) is untrusted input: a link pointing at
    // ~/.aws/credentials or /etc would otherwise pull files from outside the scan
    // root into the report.
    private static readonly EnumerationOptions WalkOptions = new()
    {
        IgnoreInaccessible = true,
        AttributesToSkip = FileAttributes.ReparsePoint,
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

        foreach (var file in EnumerateCandidateFiles(root))
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
                // Files are capped at MaxFileSizeBytes, so reading the whole file once and
                // reusing the buffer for both the binary check and line splitting is cheaper
                // than opening it twice.
                var content = await File.ReadAllBytesAsync(file.FullName, cancellationToken).ConfigureAwait(false);
                if (BinaryFileDetector.IsBinary(content))
                    continue;

                scannableFile = new ScannableFile(file.FullName, relativePath, SplitLines(content));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogWarning(ex, "Skipping unreadable file: {Path}", relativePath);
            }

            if (scannableFile is not null)
                yield return scannableFile;
        }
    }

    // Walks the tree manually so ignored directories are pruned before descending into
    // them; a large node_modules or .git is never enumerated. Only directories below the
    // scan root are matched against the ignore list, so a repository that happens to live
    // inside a folder named "build" or "packages" is still scanned.
    private static IEnumerable<FileInfo> EnumerateCandidateFiles(DirectoryInfo root)
    {
        var pending = new Stack<DirectoryInfo>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            var directory = pending.Pop();

            foreach (var subdirectory in directory.EnumerateDirectories("*", WalkOptions))
            {
                if (!IgnoredDirectoryNames.Contains(subdirectory.Name))
                    pending.Push(subdirectory);
            }

            foreach (var file in directory.EnumerateFiles("*", WalkOptions))
                yield return file;
        }
    }

    // Mirrors File.ReadAllLines: UTF-8 by default, with byte-order-mark detection for
    // UTF-16 and UTF-32 files.
    private static List<string> SplitLines(byte[] content)
    {
        using var reader = new StreamReader(new MemoryStream(content, writable: false), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var lines = new List<string>();
        while (reader.ReadLine() is { } line)
            lines.Add(line);

        return lines;
    }

    private static bool IsEligible(FileInfo file) =>
        file.Length <= MaxFileSizeBytes && !BinaryExtensions.Contains(file.Extension);
}
