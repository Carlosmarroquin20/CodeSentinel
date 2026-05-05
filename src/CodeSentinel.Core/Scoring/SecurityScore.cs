namespace CodeSentinel.Core.Scoring;

public sealed record SecurityScore(int Value, string Grade)
{
    public static SecurityScore Perfect { get; } = new(100, "A");
}
