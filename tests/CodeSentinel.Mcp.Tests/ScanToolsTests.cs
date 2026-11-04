using CodeSentinel.Application.Abstractions;
using CodeSentinel.Mcp.Security;
using CodeSentinel.Mcp.Tools;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol;

namespace CodeSentinel.Mcp.Tests;

// Runs scan_path against samples/vulnerable-repo, which produces 19 findings:
// 5 Critical, 10 High and 4 Medium across 4 files, for a score of 0 (F).
public sealed class ScanToolsTests : IDisposable
{
    private const string Sample = "samples/vulnerable-repo";

    private readonly ServiceProvider _provider = TestServices.Build();

    private ScanTools CreateTools(string allowedRoot)
    {
        var roots = AllowedRoots.Parse(["--allowed-root", allowedRoot], environmentValue: null, allowedRoot);
        return new ScanTools(
            new ScanPathValidator(roots),
            _provider.GetRequiredService<IScanOrchestrator>(),
            _provider.GetRequiredService<IIgnoreFileReader>());
    }

    [Fact]
    public async Task ScanPath_VulnerableRepo_ReturnsScoreAndCounts()
    {
        var result = await CreateTools(RepositoryPaths.Root).ScanPathAsync(Sample);

        result.Path.Should().Be(RepositoryPaths.VulnerableRepo);
        result.FilesScanned.Should().Be(4);
        result.Score.Should().Be(0);
        result.Grade.Should().Be("F");
        result.TotalFindings.Should().Be(19);
        result.FindingsBySeverity.Should().Be(new SeverityCounts(Critical: 5, High: 10, Medium: 4, Low: 0, Info: 0));
        result.MatchingFindings.Should().Be(19);
        result.ReturnedFindings.Should().Be(19);
        result.Truncated.Should().BeFalse();
    }

    [Fact]
    public async Task ScanPath_ReturnsRuleSeverityLocationAndMessage()
    {
        var result = await CreateTools(RepositoryPaths.Root).ScanPathAsync(Sample);

        result.Findings.Should().ContainEquivalentOf(new
        {
            RuleId = "CS001",
            Severity = "Critical",
            File = ".env",
            Line = 12,
            Column = 19,
            Message = "An AWS access key ID was detected. This credential provides access to AWS services.",
            Snippet = "AWS_ACCESS_KEY_ID=[REDACTED]",
        });
    }

    [Fact]
    public async Task ScanPath_UsesForwardSlashesInFilePaths()
    {
        var result = await CreateTools(RepositoryPaths.Root).ScanPathAsync(Sample);

        result.Findings.Should().Contain(finding => finding.File == "src/auth.js");
        result.Findings.Should().NotContain(finding => finding.File.Contains('\\', StringComparison.Ordinal));
    }

    [Fact]
    public async Task ScanPath_OrdersFindingsFromMostToLeastSevere()
    {
        var result = await CreateTools(RepositoryPaths.Root).ScanPathAsync(Sample);

        result.Findings.Select(finding => Enum.Parse<Core.Findings.Severity>(finding.Severity))
            .Should().BeInDescendingOrder();
    }

    [Theory]
    [InlineData("High", 15)]
    [InlineData("critical", 5)]
    [InlineData(" Medium ", 19)]
    public async Task ScanPath_MinSeverity_FiltersFindingsButNotTheScore(string minSeverity, int expected)
    {
        var result = await CreateTools(RepositoryPaths.Root).ScanPathAsync(Sample, minSeverity);

        result.MatchingFindings.Should().Be(expected);
        result.Findings.Should().HaveCount(expected);
        result.TotalFindings.Should().Be(19);
        result.Score.Should().Be(0);
        result.FindingsBySeverity.High.Should().Be(10);
    }

    [Theory]
    [InlineData("Severe")]
    [InlineData("4")]
    [InlineData("99")]
    public async Task ScanPath_UnknownSeverity_IsRejected(string minSeverity)
    {
        var act = () => CreateTools(RepositoryPaths.Root).ScanPathAsync(Sample, minSeverity);

        await act.Should().ThrowAsync<McpException>()
            .WithMessage("Unknown severity*Info, Low, Medium, High, Critical*");
    }

    [Fact]
    public async Task ScanPath_MaxFindings_KeepsTheMostSevereAndReportsTruncation()
    {
        var result = await CreateTools(RepositoryPaths.Root).ScanPathAsync(Sample, maxFindings: 3);

        result.Findings.Should().HaveCount(3);
        result.Findings.Should().OnlyContain(finding => finding.Severity == "Critical");
        result.ReturnedFindings.Should().Be(3);
        result.MatchingFindings.Should().Be(19);
        result.Truncated.Should().BeTrue();
    }

    [Fact]
    public async Task ScanPath_MaxFindingsZero_ReturnsOnlyTheSummary()
    {
        var result = await CreateTools(RepositoryPaths.Root).ScanPathAsync(Sample, maxFindings: 0);

        result.Findings.Should().BeEmpty();
        result.TotalFindings.Should().Be(19);
        result.Truncated.Should().BeTrue();
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(501)]
    public async Task ScanPath_MaxFindingsOutOfRange_IsRejected(int maxFindings)
    {
        var act = () => CreateTools(RepositoryPaths.Root).ScanPathAsync(Sample, maxFindings: maxFindings);

        await act.Should().ThrowAsync<McpException>().WithMessage("maxFindings must be between 0 and 500*");
    }

    [Fact]
    public async Task ScanPath_PathOutsideAllowedRoot_IsRejected()
    {
        var act = () => CreateTools(RepositoryPaths.VulnerableRepo).ScanPathAsync("../../src");

        await act.Should().ThrowAsync<McpException>().WithMessage("*outside the allowed roots*");
    }

    [Fact]
    public async Task ScanPath_HonoursIgnoreFileUnlessDisabled()
    {
        using var workspace = new TempWorkspace();
        workspace.Write("legacy/keys.txt", "aws_key = AKIAIOSFODNN7EXAMPLE");
        workspace.Write(".codesentinelignore", "legacy/**");
        var tools = CreateTools(workspace.Root);

        var honoured = await tools.ScanPathAsync(".");
        var ignored = await tools.ScanPathAsync(".", useIgnoreFile: false);

        honoured.TotalFindings.Should().Be(0);
        ignored.Findings.Should().Contain(finding => finding.RuleId == "CS001");
    }

    [Fact]
    public async Task ScanPath_HonoursInlineSuppressionsUnlessDisabled()
    {
        using var workspace = new TempWorkspace();
        workspace.Write("keys.txt", "aws_key = AKIAIOSFODNN7EXAMPLE  # codesentinel:ignore");
        var tools = CreateTools(workspace.Root);

        var honoured = await tools.ScanPathAsync(".");
        var reported = await tools.ScanPathAsync(".", honorInlineSuppressions: false);

        honoured.TotalFindings.Should().Be(0);
        reported.Findings.Should().Contain(finding => finding.RuleId == "CS001");
    }

    public void Dispose() => _provider.Dispose();

    private sealed class TempWorkspace : IDisposable
    {
        public string Root { get; } = Directory.CreateTempSubdirectory("cs-mcp-scan-").FullName;

        public void Write(string relativePath, string content)
        {
            var path = Path.Combine(Root, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, content);
        }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
