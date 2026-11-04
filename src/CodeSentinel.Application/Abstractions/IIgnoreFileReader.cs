namespace CodeSentinel.Application.Abstractions;

// Reads the glob patterns a repository declares in its .codesentinelignore file.
// Callers decide whether to honour the file at all: for a repository you do not
// control it is written by the people whose code is being checked (ADR 0006).
public interface IIgnoreFileReader
{
    public const string FileName = ".codesentinelignore";

    // Returns the non-empty, non-comment lines of the file in the scan root, or an
    // empty list when the file does not exist or cannot be read.
    IReadOnlyList<string> ReadPatterns(string scanRoot);
}
