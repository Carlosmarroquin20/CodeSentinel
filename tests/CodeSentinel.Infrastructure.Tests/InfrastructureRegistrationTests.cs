using CodeSentinel.Infrastructure.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Infrastructure.Tests;

public class InfrastructureRegistrationTests
{
    [Fact]
    public void AddCodeSentinelInfrastructure_RegistersWithoutThrowing()
    {
        var services = new ServiceCollection();

        var act = () => services.AddCodeSentinelInfrastructure();

        act.Should().NotThrow();
    }
}
