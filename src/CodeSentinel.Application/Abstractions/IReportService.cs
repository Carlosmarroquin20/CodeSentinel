using CodeSentinel.Core.Reporting;

namespace CodeSentinel.Application.Abstractions;

public interface IReportService
{
    IReadOnlyCollection<string> SupportedFormats { get; }

    Task WriteReportAsync(
        ScanReport report,
        string outputPath,
        string format,
        CancellationToken cancellationToken);
}
