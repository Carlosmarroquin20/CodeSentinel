using CodeSentinel.Core.Scoring;

namespace CodeSentinel.Core.Tests;

public class SecurityScoreTests
{
    [Fact]
    public void Perfect_ReturnsMaximumScore()
    {
        SecurityScore.Perfect.Value.Should().Be(100);
        SecurityScore.Perfect.Grade.Should().Be("A");
    }
}
