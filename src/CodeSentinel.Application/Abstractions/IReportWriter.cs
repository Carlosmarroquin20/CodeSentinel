using CodeSentinel.Core.Reporting;

namespace CodeSentinel.Application.Abstractions;

public interface IReportWriter
{
    /// <summary>Format identifier used to select this writer (e.g., "json", "html").</summary>
    string Format { get; }

    Task WriteAsync(ScanReport report, Stream output, CancellationToken cancellationToken);
}
