using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace CodeSentinel.Mcp.Tests.Security;

// Creates a directory link for the path validation tests. Symbolic links need Developer
// Mode or elevation on Windows, so a junction (mount point) is created there instead,
// directly through FSCTL_SET_REPARSE_POINT. Starting cmd.exe for "mklink /J" failed
// intermittently with STATUS_DLL_INIT_FAILED while test assemblies ran in parallel.
internal static class DirectoryLinks
{
    private const uint GenericWrite = 0x40000000;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FsctlSetReparsePoint = 0x000900A4;
    private const uint IoReparseTagMountPoint = 0xA0000003;

    public static void Create(string link, string target)
    {
        if (!OperatingSystem.IsWindows())
        {
            Directory.CreateSymbolicLink(link, target);
            return;
        }

        Directory.CreateDirectory(link);

        using var handle = CreateFileW(
            link, GenericWrite, 0, IntPtr.Zero, OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid)
            throw new IOException($"Could not open {link}", Marshal.GetHRForLastWin32Error());

        var buffer = BuildMountPointBuffer(Path.GetFullPath(target));
        if (!DeviceIoControl(handle, FsctlSetReparsePoint, buffer, buffer.Length, IntPtr.Zero, 0, out _, IntPtr.Zero))
            throw new IOException($"Could not turn {link} into a junction", Marshal.GetHRForLastWin32Error());
    }

    // REPARSE_DATA_BUFFER for a mount point: tag, data length, reserved, then the
    // substitute name (\??\C:\target) and print name, each NUL-terminated UTF-16.
    private static byte[] BuildMountPointBuffer(string target)
    {
        var substitute = Encoding.Unicode.GetBytes(@"\??\" + target);
        var print = Encoding.Unicode.GetBytes(target);
        const int Terminator = 2;
        var pathBufferLength = substitute.Length + Terminator + print.Length + Terminator;
        var dataLength = 8 + pathBufferLength;

        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(IoReparseTagMountPoint);
        writer.Write((ushort)dataLength);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)substitute.Length);
        writer.Write((ushort)(substitute.Length + Terminator));
        writer.Write((ushort)print.Length);
        writer.Write(substitute);
        writer.Write((ushort)0);
        writer.Write(print);
        writer.Write((ushort)0);
        writer.Flush();

        return stream.ToArray();
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint ioControlCode,
        byte[] inBuffer,
        int inBufferSize,
        IntPtr outBuffer,
        int outBufferSize,
        out int bytesReturned,
        IntPtr overlapped);
}
