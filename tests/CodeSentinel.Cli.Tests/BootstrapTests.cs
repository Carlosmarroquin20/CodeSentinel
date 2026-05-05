using CodeSentinel.Application.Abstractions;
using CodeSentinel.Cli;
using Microsoft.Extensions.DependencyInjection;

namespace CodeSentinel.Cli.Tests;

public class BootstrapTests
{
    [Fact]
    public void BuildServiceProvider_ResolvesScanOrchestrator()
    {
        using var provider = Bootstrap.BuildServiceProvider();

        var orchestrator = provider.GetService<IScanOrchestrator>();

        orchestrator.Should().NotBeNull();
    }
}
