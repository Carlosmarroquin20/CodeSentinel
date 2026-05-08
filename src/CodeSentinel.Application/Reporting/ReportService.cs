using CodeSentinel.Application.Abstractions;
using CodeSentinel.Core.Reporting;
using Microsoft.Extensions.Logging;

namespace CodeSentinel.Application.Reporting;

internal sealed class ReportService : IReportService
{
    private readonly IReadOnlyDictionary<string, IReportWriter> _writers;
    private readonly ILogger<ReportService> _logger;

    public ReportService(IEnumerable<IReportWriter> writers, ILogger<ReportService> logger)
    {
        _writers = writers.ToDictionary(w => w.Format, StringComparer.OrdinalIgnoreCase);
        _logger = logger;
    }

    public IReadOnlyCollection<string> SupportedFormats => _writers.Keys.ToList();

    public async Task WriteReportAsync(
        ScanReport report,
        string outputPath,
        string format,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(format);

        if (!_writers.TryGetValue(format, out var writer))
        {
            var available = string.Join(", ", _writers.Keys);
            throw new NotSupportedException(
                $"Report format '{format}' is not supported. Available formats: {available}");
        }

        var directory = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        _logger.LogInformation("Writing {Format} report to {Path}", format, outputPath);

        await using var stream = File.Create(outputPath);
        await writer.WriteAsync(report, stream, cancellationToken).ConfigureAwait(false);

        _logger.LogInformation("Report written successfully");
    }
}
