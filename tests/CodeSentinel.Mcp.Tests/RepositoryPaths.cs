namespace CodeSentinel.Mcp.Tests;

internal static class RepositoryPaths
{
    public static string Root { get; } = FindRoot();

    public static string VulnerableRepo { get; } = Path.Combine(Root, "samples", "vulnerable-repo");

    private static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "CodeSentinel.sln")))
            directory = directory.Parent;

        return directory?.FullName
            ?? throw new InvalidOperationException("Could not find CodeSentinel.sln above the test output directory.");
    }
}
