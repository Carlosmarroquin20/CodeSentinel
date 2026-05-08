namespace CodeSentinel.Application.Abstractions;

public interface IIgnorePolicy
{
    bool ShouldIgnore(string relativePath);
}
