namespace CodeSentinel.Infrastructure.FileSystem;

internal static class BinaryFileDetector
{
    private const int BytesToSample = 8192;

    public static async Task<bool> IsBinaryAsync(FileInfo file, CancellationToken cancellationToken)
    {
        if (file.Length == 0)
            return false;

        var sampleSize = (int)Math.Min(file.Length, BytesToSample);
        var buffer = new byte[sampleSize];

        await using var stream = file.OpenRead();
        var bytesRead = await stream.ReadAsync(buffer.AsMemory(0, sampleSize), cancellationToken).ConfigureAwait(false);

        // A null byte in the first sample is a reliable indicator of binary content.
        return buffer.AsSpan(0, bytesRead).Contains((byte)0);
    }
}
