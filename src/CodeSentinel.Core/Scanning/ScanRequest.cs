namespace CodeSentinel.Core.Scanning;

public sealed record ScanRequest(string RootPath, IReadOnlyCollection<string> IgnoreGlobs)
{
    public static ScanRequest ForPath(string rootPath) =>
        new(rootPath, Array.Empty<string>());
}
