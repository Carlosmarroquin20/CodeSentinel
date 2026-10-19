namespace CodeSentinel.Infrastructure.FileSystem;

internal static class BinaryFileDetector
{
    private const int BytesToSample = 8192;

    // A null byte in the first sample is a reliable indicator of binary content.
    public static bool IsBinary(ReadOnlySpan<byte> content) =>
        content[..Math.Min(content.Length, BytesToSample)].Contains((byte)0);
}
