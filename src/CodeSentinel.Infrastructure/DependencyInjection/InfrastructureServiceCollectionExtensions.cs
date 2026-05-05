using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Infrastructure.DependencyInjection;

public static class InfrastructureServiceCollectionExtensions
{
    public static IServiceCollection AddCodeSentinelInfrastructure(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // File sources, rule providers, and report writers register here as detection
        // and reporting capabilities are introduced in later phases.
        return services;
    }
}
