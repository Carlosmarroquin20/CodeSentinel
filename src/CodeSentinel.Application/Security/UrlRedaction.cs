namespace CodeSentinel.Application.Security;

public static class UrlRedaction
{
    private const string Mask = "***";

    // Remote URLs may embed credentials (https://<token>@host/repo.git). Anything that
    // echoes the URL back to the user, such as logs and report headers, must go through
    // this first. The conventional "git" user carries no secret and is kept for clarity.
    public static string RedactUserInfo(string url)
    {
        ArgumentNullException.ThrowIfNull(url);

        var schemeEnd = url.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd < 0)
            return url;

        var authorityStart = schemeEnd + 3;
        var authorityEnd = url.IndexOfAny(['/', '?', '#'], authorityStart);
        if (authorityEnd < 0)
            authorityEnd = url.Length;

        var at = url.LastIndexOf('@', authorityEnd - 1, authorityEnd - authorityStart);
        if (at < 0)
            return url;

        var userInfo = url[authorityStart..at];
        if (string.Equals(userInfo, "git", StringComparison.Ordinal))
            return url;

        return string.Concat(url.AsSpan(0, authorityStart), Mask, url.AsSpan(at));
    }
}
