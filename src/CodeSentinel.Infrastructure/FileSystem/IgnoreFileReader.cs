using CodeSentinel.Application.Abstractions;
using Microsoft.Extensions.Logging;

namespace CodeSentinel.Infrastructure.FileSystem;

internal sealed class IgnoreFileReader : IIgnoreFileReader
{
    private readonly ILogger<IgnoreFileReader> _logger;

    public IgnoreFileReader(ILogger<IgnoreFileReader> logger)
    {
        _logger = logger;
    }

    public IReadOnlyList<string> ReadPatterns(string scanRoot)
    {
        ArgumentNullException.ThrowIfNull(scanRoot);

        var ignoreFile = new FileInfo(Path.Combine(scanRoot, IIgnoreFileReader.FileName));
        if (!ignoreFile.Exists)
            return [];

        try
        {
            var patterns = File.ReadAllLines(ignoreFile.FullName)
                .Select(line => line.Trim())
                .Where(line => line.Length > 0 && !line.StartsWith('#'))
                .ToList();

            if (patterns.Count > 0)
                _logger.LogInformation("Loaded {Count} pattern(s) from {File}", patterns.Count, IIgnoreFileReader.FileName);

            return patterns;
        }
        catch (IOException ex)
        {
            _logger.LogWarning(ex, "Could not read {File}; proceeding without it", IIgnoreFileReader.FileName);
            return [];
        }
    }
}
