using CodeSentinel.Mcp.Tools;

namespace CodeSentinel.Mcp.Tests;

// Recovers the raw secret behind each redacted snippet by comparing the snippet with
// the original line in the fixture. Tests then assert that none of those values appear
// anywhere in what the server sends to the agent.
internal static class FixtureSecrets
{
    public const string Marker = "[REDACTED]";

    // A few values from samples/vulnerable-repo, listed explicitly so the tests do not
    // depend only on the recovery logic below being right.
    public static IReadOnlyList<string> Known { get; } =
    [
        "AKIAIOSFODNN7EXAMPLE",
        "SuperSecr3tDbPassw0rd!",
        "ghp_FakeFakeFakeFakeFakeFakeFakeFake1234",
        "sk_test_FakeStripeSecretKey123456789012",
        "my-super-secret-token-value-xyz",
        "xoxb-fakeSlackBotTokenForDemo1234567890",
    ];

    public static IReadOnlyList<string> Recover(string scanRoot, IEnumerable<FindingSummary> findings)
    {
        var secrets = new List<string>();

        foreach (var finding in findings)
        {
            var snippet = finding.Snippet;
            if (snippet is null)
                continue;

            var markerIndex = snippet.IndexOf(Marker, StringComparison.Ordinal);
            if (markerIndex < 0)
                continue;

            var line = File.ReadAllLines(Path.Combine(scanRoot, finding.File))[finding.Line - 1].TrimEnd();
            var before = snippet[..markerIndex];
            var after = snippet[(markerIndex + Marker.Length)..];

            if (!line.StartsWith(before, StringComparison.Ordinal) || !line.EndsWith(after, StringComparison.Ordinal))
                throw new InvalidOperationException($"Snippet does not match {finding.File}:{finding.Line}");

            secrets.Add(line[before.Length..(line.Length - after.Length)]);
        }

        return secrets;
    }
}
