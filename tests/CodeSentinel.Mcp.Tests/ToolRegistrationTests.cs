using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Server;

namespace CodeSentinel.Mcp.Tests;

public sealed class ToolRegistrationTests
{
    [Theory]
    [InlineData("list_rules")]
    [InlineData("scan_path")]
    [InlineData("explain_rule")]
    public void Server_RegistersToolAsReadOnly(string name)
    {
        var tool = GetTool(name);

        tool.ProtocolTool.Description.Should().NotBeNullOrWhiteSpace();
        tool.ProtocolTool.Annotations!.ReadOnlyHint.Should().BeTrue();
        tool.ProtocolTool.Annotations.DestructiveHint.Should().BeFalse();
        tool.ProtocolTool.Annotations.OpenWorldHint.Should().BeFalse();
    }

    [Fact]
    public void ScanPath_RequiresOnlyThePath()
    {
        var schema = GetTool("scan_path").ProtocolTool.InputSchema;

        var properties = schema.GetProperty("properties").EnumerateObject().Select(p => p.Name);
        properties.Should().BeEquivalentTo(
            "path", "minSeverity", "maxFindings", "useIgnoreFile", "honorInlineSuppressions");

        var required = schema.GetProperty("required").EnumerateArray().Select(e => e.GetString());
        required.Should().Equal("path");
    }

    [Fact]
    public void ScanPath_DescribesEveryParameter()
    {
        var properties = GetTool("scan_path").ProtocolTool.InputSchema.GetProperty("properties");

        foreach (var property in properties.EnumerateObject())
        {
            property.Value.TryGetProperty("description", out var description).Should().BeTrue(property.Name);
            description.GetString().Should().NotBeNullOrWhiteSpace();
        }
    }

    private static McpServerTool GetTool(string name)
    {
        using var host = McpServerHost.Build([]);
        var tools = host.Services.GetRequiredService<IOptions<McpServerOptions>>().Value.ToolCollection;

        tools.Should().NotBeNull();
        return tools!.Should().ContainSingle(tool => tool.ProtocolTool.Name == name).Subject;
    }
}
