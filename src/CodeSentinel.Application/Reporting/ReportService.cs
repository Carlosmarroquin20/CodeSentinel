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

        // Write to a sibling temp file and move it into place only once the writer has
        // finished. A failed or cancelled write must not leave a truncated report behind:
        // CI steps such as SARIF upload run even when the scan step fails and would pick
        // it up as if it were complete.
        var tempPath = outputPath + ".tmp";
        try
        {
            await using (var stream = File.Create(tempPath))
            {
                await writer.WriteAsync(report, stream, cancellationToken).ConfigureAwait(false);
            }

            File.Move(tempPath, outputPath, overwrite: true);
        }
        catch
        {
            TryDelete(tempPath);
            throw;
        }

        _logger.LogInformation("Report written successfully");
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // Best effort: the original exception is the one worth surfacing.
        }
        catch (UnauthorizedAccessException)
        {
            // Same as above.
        }
    }
}
