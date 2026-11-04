using ModelContextProtocol;

namespace CodeSentinel.Mcp.Security;

// The path in a scan_path call comes from the model, which may be acting on text it
// read in an untrusted repository (ADR 0006). It is accepted only if it names an
// existing directory inside an allowed root, reached without crossing a symbolic link
// or junction. Rejections are McpException so the message reaches the agent as a tool
// error it can act on.
internal sealed class ScanPathValidator
{
    private readonly AllowedRoots _roots;

    public ScanPathValidator(AllowedRoots roots)
    {
        _roots = roots;
    }

    public string Resolve(string? requestedPath)
    {
        if (string.IsNullOrWhiteSpace(requestedPath))
            throw Reject("A path is required.");

        if (requestedPath.Contains('\0', StringComparison.Ordinal))
            throw Reject("The path contains a null character.");

        if (LooksLikeRemote(requestedPath))
            throw Reject("Remote repositories are not supported. Pass a local directory path.");

        // UNC shares and Win32 device paths (\\?\, \\.\) can reach other machines or skip
        // normalization, so they are refused on every platform.
        if (requestedPath.StartsWith(@"\\", StringComparison.Ordinal)
            || requestedPath.StartsWith("//", StringComparison.Ordinal))
            throw Reject("UNC and device paths are not allowed.");

        string fullPath;
        try
        {
            // Relative paths are anchored to the first allowed root, not to the process
            // working directory, so they cannot start outside the roots.
            fullPath = AllowedRoots.Normalize(Path.GetFullPath(requestedPath, _roots.Paths[0]));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw Reject("The path is not valid.");
        }

        var root = _roots.FindContainingRoot(fullPath)
            ?? throw Reject($"The path {fullPath} is outside the allowed roots.");

        if (!Directory.Exists(fullPath))
        {
            throw Reject(File.Exists(fullPath)
                ? $"The path {fullPath} is a file. Pass the directory that contains it."
                : $"The directory {fullPath} does not exist.");
        }

        EnsureNoLinkBelowRoot(fullPath, root);
        return fullPath;
    }

    // A symbolic link or junction inside a root can point anywhere on the machine. The
    // file walker never follows links below the scan root (ADR 0006); this closes the
    // same gap for the scan root itself and its ancestors up to the allowed root.
    private void EnsureNoLinkBelowRoot(string fullPath, string root)
    {
        var current = new DirectoryInfo(fullPath);
        while (current is not null
               && !string.Equals(AllowedRoots.Normalize(current.FullName), root, AllowedRoots.PathComparison))
        {
            if (current.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw Reject($"The path crosses a symbolic link or junction at {current.FullName}.");

            current = current.Parent;
        }
    }

    private static bool LooksLikeRemote(string path) =>
        path.Contains("://", StringComparison.Ordinal)
        || path.StartsWith("git@", StringComparison.OrdinalIgnoreCase);

    private McpException Reject(string reason) =>
        new($"{reason} Allowed roots: {string.Join(", ", _roots.Paths)}");
}
