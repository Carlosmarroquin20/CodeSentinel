namespace CodeSentinel.Core.Detection;

public sealed record ScannableFile(
    string FullPath,
    string RelativePath,
    IReadOnlyList<string> Lines)
{
    public string Extension => Path.GetExtension(FullPath).ToLowerInvariant();
    public string FileName => Path.GetFileName(FullPath);
    public int LineCount => Lines.Count;
}
