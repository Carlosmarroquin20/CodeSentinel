using CodeSentinel.Application.Abstractions;
using CodeSentinel.Application.Scanning;
using CodeSentinel.Application.Scoring;
using CodeSentinel.Core.Scoring;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Application.DependencyInjection;

public static class ApplicationServiceCollectionExtensions
{
    public static IServiceCollection AddCodeSentinelApplication(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<ISecurityScorePolicy, DefaultSecurityScorePolicy>();
        services.AddSingleton<IScanOrchestrator, ScanOrchestrator>();

        return services;
    }
}
