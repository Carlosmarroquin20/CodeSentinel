using CodeSentinel.Application.Abstractions;
using CodeSentinel.Infrastructure.FileSystem;
using CodeSentinel.Infrastructure.Reporting.Html;
using CodeSentinel.Infrastructure.Reporting.Json;
using CodeSentinel.Infrastructure.Rules;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Infrastructure.DependencyInjection;

public static class InfrastructureServiceCollectionExtensions
{
    public static IServiceCollection AddCodeSentinelInfrastructure(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<IIgnorePolicy, NullIgnorePolicy>();
        services.AddSingleton<IFileSource, LocalFileSource>();
        services.AddSingleton<IRuleProvider, BuiltInRuleProvider>();
        services.AddSingleton<IReportWriter, JsonReportWriter>();
        services.AddSingleton<IReportWriter, HtmlReportWriter>();

        return services;
    }
}
