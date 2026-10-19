namespace CodeSentinel.Core.Scanning;

// HonorInlineSuppressions controls whether "codesentinel:ignore" comments in the
// scanned files may drop findings. Turn it off for repositories you do not control.
public sealed record ScanRequest(
    string RootPath,
    IReadOnlyCollection<string> IgnoreGlobs,
    bool HonorInlineSuppressions = true)
{
    public static ScanRequest ForPath(string rootPath) =>
        new(rootPath, Array.Empty<string>());
}
