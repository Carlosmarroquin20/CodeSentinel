// Sample vulnerable cryptographic code — used only for testing and demonstration.
// This file intentionally contains patterns that CodeSentinel is designed to detect.

using System.Security.Cryptography;
using System.Text;

namespace VulnerableApp;

public class InsecurePasswordHasher
{
    // CS101: MD5 is cryptographically broken and must not be used for password hashing.
    public string HashWithMd5(string password)
    {
        using var md5 = MD5.Create();
        var bytes = Encoding.UTF8.GetBytes(password);
        return Convert.ToHexString(md5.ComputeHash(bytes));
    }

    // CS101: SHA-1 is also broken for security purposes.
    public string HashWithSha1(string password)
    {
        using var sha1 = SHA1.Create();
        var bytes = Encoding.UTF8.GetBytes(password);
        return Convert.ToHexString(sha1.ComputeHash(bytes));
    }
}
