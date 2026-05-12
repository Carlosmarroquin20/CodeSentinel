using CodeSentinel.Application.Abstractions;
using CodeSentinel.Infrastructure.FileSystem;
using CodeSentinel.Infrastructure.Reporting.Html;
using CodeSentinel.Infrastructure.Reporting.Json;
using CodeSentinel.Infrastructure.Reporting.Sarif;
using CodeSentinel.Infrastructure.Rules;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Infrastructure.DependencyInjection;

public static class InfrastructureServiceCollectionExtensions
{
    public static IServiceCollection AddCodeSentinelInfrastructure(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // IIgnorePolicy is no longer registered here: LocalFileSource builds it per-scan
        // from ScanRequest.IgnoreGlobs so --exclude and .codesentinelignore patterns
        // flow through the request rather than through DI.
        services.AddSingleton<IFileSource, LocalFileSource>();
        services.AddSingleton<IRuleProvider, BuiltInRuleProvider>();
        services.AddSingleton<IReportWriter, JsonReportWriter>();
        services.AddSingleton<IReportWriter, HtmlReportWriter>();
        services.AddSingleton<IReportWriter, SarifReportWriter>();

        return services;
    }
}
