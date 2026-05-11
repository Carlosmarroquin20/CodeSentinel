namespace CodeSentinel.Cli;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var level = Bootstrap.ResolveLogLevel(args);
        await using var provider = Bootstrap.BuildServiceProvider(level);
        return await CliApplication.RunAsync(args, provider).ConfigureAwait(false);
    }
}
