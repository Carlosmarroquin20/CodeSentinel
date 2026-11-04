namespace CodeSentinel.Mcp.Security;

// The directories scan_path may read from. Configured by whoever launches the server,
// never by the agent: --allowed-root on the command line (repeatable) takes precedence,
// then the CODESENTINEL_MCP_ALLOWED_ROOTS environment variable (entries separated by
// Path.PathSeparator), and the working directory when neither is set.
internal sealed class AllowedRoots
{
    public const string ArgumentName = "--allowed-root";
    public const string EnvironmentVariable = "CODESENTINEL_MCP_ALLOWED_ROOTS";

    private AllowedRoots(IReadOnlyList<string> paths)
    {
        Paths = paths;
    }

    // Absolute and normalized, without a trailing separator unless the root is a volume root.
    public IReadOnlyList<string> Paths { get; }

    // Case-insensitive where the default file system is (Windows, macOS). On Linux a
    // case-insensitive comparison would let /srv/Repo match a root of /srv/repo.
    public static StringComparison PathComparison { get; } =
        OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

    public static AllowedRoots Parse(IReadOnlyList<string> args, string? environmentValue, string workingDirectory)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(workingDirectory);

        var configured = ParseArguments(args);
        if (configured.Count == 0 && !string.IsNullOrWhiteSpace(environmentValue))
        {
            configured = environmentValue
                .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();
        }

        if (configured.Count == 0)
            configured = [workingDirectory];

        var comparer = StringComparer.FromComparison(PathComparison);
        var roots = new List<string>();
        foreach (var path in configured)
        {
            if (!Path.IsPathFullyQualified(path))
                throw new ArgumentException($"Allowed root must be an absolute path: {path}");

            var normalized = Normalize(path);
            if (!Directory.Exists(normalized))
                throw new ArgumentException($"Allowed root does not exist or is not a directory: {normalized}");

            if (!roots.Contains(normalized, comparer))
                roots.Add(normalized);
        }

        return new AllowedRoots(roots);
    }

    public static string Normalize(string path) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

    // Returns the root that contains the normalized path, or null. Comparing against
    // root + separator keeps a root of /srv/repo from matching /srv/repo-backup.
    public string? FindContainingRoot(string normalizedPath)
    {
        ArgumentNullException.ThrowIfNull(normalizedPath);

        foreach (var root in Paths)
        {
            if (string.Equals(normalizedPath, root, PathComparison))
                return root;

            var prefix = Path.EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar;
            if (normalizedPath.StartsWith(prefix, PathComparison))
                return root;
        }

        return null;
    }

    private static List<string> ParseArguments(IReadOnlyList<string> args)
    {
        var roots = new List<string>();

        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            if (arg == ArgumentName)
            {
                if (i + 1 >= args.Count || string.IsNullOrWhiteSpace(args[i + 1]))
                    throw new ArgumentException($"{ArgumentName} requires a directory path.");

                roots.Add(args[++i]);
            }
            else if (arg.StartsWith(ArgumentName + "=", StringComparison.Ordinal))
            {
                var value = arg[(ArgumentName.Length + 1)..];
                if (string.IsNullOrWhiteSpace(value))
                    throw new ArgumentException($"{ArgumentName} requires a directory path.");

                roots.Add(value);
            }
            else
            {
                throw new ArgumentException(
                    $"Unknown argument: {arg}. The only supported option is {ArgumentName} <path>.");
            }
        }

        return roots;
    }
}
