namespace CodeSentinel.Cli;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        await using var provider = Bootstrap.BuildServiceProvider();
        return await CliApplication.RunAsync(args, provider).ConfigureAwait(false);
    }
}
