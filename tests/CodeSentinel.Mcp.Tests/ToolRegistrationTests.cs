using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Server;

namespace CodeSentinel.Mcp.Tests;

public sealed class ToolRegistrationTests
{
    [Fact]
    public void Server_RegistersListRulesAsReadOnly()
    {
        using var host = McpServerHost.Build([]);
        var tools = host.Services.GetRequiredService<IOptions<McpServerOptions>>().Value.ToolCollection;

        tools.Should().NotBeNull();
        var listRules = tools!.Should().ContainSingle(tool => tool.ProtocolTool.Name == "list_rules").Subject;
        listRules.ProtocolTool.Description.Should().NotBeNullOrWhiteSpace();
        listRules.ProtocolTool.Annotations!.ReadOnlyHint.Should().BeTrue();
        listRules.ProtocolTool.Annotations.DestructiveHint.Should().BeFalse();
    }
}
