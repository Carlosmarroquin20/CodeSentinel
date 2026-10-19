namespace CodeSentinel.Infrastructure.FileSystem;

internal static class BinaryFileDetector
{
    private const int BytesToSample = 8192;

    // A null byte in the first sample is a reliable indicator of binary content, except
    // in UTF-16 and UTF-32 text, where nulls are part of normal ASCII characters. Those
    // files are recognised by their byte-order mark and treated as text.
    public static bool IsBinary(ReadOnlySpan<byte> content)
    {
        if (StartsWithWideByteOrderMark(content))
            return false;

        return content[..Math.Min(content.Length, BytesToSample)].Contains((byte)0);
    }

    private static bool StartsWithWideByteOrderMark(ReadOnlySpan<byte> content) =>
        content.StartsWith((ReadOnlySpan<byte>)[0xFF, 0xFE]) ||
        content.StartsWith((ReadOnlySpan<byte>)[0xFE, 0xFF]) ||
        content.StartsWith((ReadOnlySpan<byte>)[0x00, 0x00, 0xFE, 0xFF]);
}
