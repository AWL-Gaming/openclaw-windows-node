using System.Text;
using System.Text.Json;
using OpenClaw.Shared;
using OpenClaw.Shared.Capabilities;
using Xunit;

namespace OpenClaw.Shared.Tests;

public sealed class HostCapabilityFileReadTests
{
    [Fact]
    public async Task FileRead_ReturnsBoundedPngPayload()
    {
        using var root = new TemporaryDirectory();
        var path = Path.Combine(root.Path, "sample.png");
        var bytes = new byte[] { 0x89, (byte)'P', (byte)'N', (byte)'G', 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4 };
        await File.WriteAllBytesAsync(path, bytes);

        var capability = new HostCapability(NullLogger.Instance, [root.Path]);
        var response = await capability.ExecuteAsync(Request(path));

        Assert.True(response.Ok, response.Error);
        using var payload = JsonDocument.Parse(JsonSerializer.Serialize(response.Payload));
        var value = payload.RootElement;
        Assert.Equal("sample.png", value.GetProperty("fileName").GetString());
        Assert.Equal(bytes.Length, value.GetProperty("sizeBytes").GetInt32());
        Assert.Equal("image/png", value.GetProperty("mimeType").GetString());
        Assert.Equal(64, value.GetProperty("sha256").GetString()?.Length);
        Assert.Equal(Convert.ToBase64String(bytes), value.GetProperty("base64").GetString());
    }

    [Fact]
    public async Task FileRead_ReturnsUtf8TextPayload()
    {
        using var root = new TemporaryDirectory();
        var path = Path.Combine(root.Path, "sample.txt");
        var bytes = Encoding.UTF8.GetBytes("hello\nworld");
        await File.WriteAllBytesAsync(path, bytes);

        var capability = new HostCapability(NullLogger.Instance, [root.Path]);
        var response = await capability.ExecuteAsync(Request(path));

        Assert.True(response.Ok, response.Error);
        using var payload = JsonDocument.Parse(JsonSerializer.Serialize(response.Payload));
        var value = payload.RootElement;
        Assert.Equal("text/plain; charset=utf-8", value.GetProperty("mimeType").GetString());
        Assert.Equal(Convert.ToBase64String(bytes), value.GetProperty("base64").GetString());
    }

    [Fact]
    public async Task FileRead_ReturnsUtf16LeTextPayload()
    {
        using var root = new TemporaryDirectory();
        var path = Path.Combine(root.Path, "sample-utf16.txt");
        var body = Encoding.Unicode.GetBytes("hello\r\nworld");
        var bytes = new byte[body.Length + 2];
        bytes[0] = 0xFF;
        bytes[1] = 0xFE;
        Buffer.BlockCopy(body, 0, bytes, 2, body.Length);
        await File.WriteAllBytesAsync(path, bytes);

        var capability = new HostCapability(NullLogger.Instance, [root.Path]);
        var response = await capability.ExecuteAsync(Request(path));

        Assert.True(response.Ok, response.Error);
        using var payload = JsonDocument.Parse(JsonSerializer.Serialize(response.Payload));
        Assert.Equal(
            "text/plain; charset=utf-16le",
            payload.RootElement.GetProperty("mimeType").GetString());
    }

    [Fact]
    public async Task FileRead_LeavesBinaryPayloadAsOctetStream()
    {
        using var root = new TemporaryDirectory();
        var path = Path.Combine(root.Path, "sample.bin");
        await File.WriteAllBytesAsync(path, [0x00, 0x01, 0x02, 0x03, 0xFF]);

        var capability = new HostCapability(NullLogger.Instance, [root.Path]);
        var response = await capability.ExecuteAsync(Request(path));

        Assert.True(response.Ok, response.Error);
        using var payload = JsonDocument.Parse(JsonSerializer.Serialize(response.Payload));
        Assert.Equal(
            "application/octet-stream",
            payload.RootElement.GetProperty("mimeType").GetString());
    }

    [Fact]
    public async Task FileRead_RejectsOutsideApprovedRoot()
    {
        using var root = new TemporaryDirectory();
        using var outside = new TemporaryDirectory();
        var path = Path.Combine(outside.Path, "outside.png");
        await File.WriteAllBytesAsync(path, [0x89, (byte)'P', (byte)'N', (byte)'G', 0x0D, 0x0A, 0x1A, 0x0A]);

        var capability = new HostCapability(NullLogger.Instance, [root.Path]);
        var response = await capability.ExecuteAsync(Request(path));

        Assert.False(response.Ok);
        Assert.Contains("outside approved read roots", response.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FileRead_RejectsPrivateKeyPathAndContent()
    {
        using var root = new TemporaryDirectory();
        var keyPath = Path.Combine(root.Path, "server.key");
        await File.WriteAllTextAsync(keyPath, "not-secret-test-data");
        var contentPath = Path.Combine(root.Path, "payload.bin");
        await File.WriteAllTextAsync(contentPath, "-----BEGIN " + "PRIVATE KEY-----\ntest");

        var capability = new HostCapability(NullLogger.Instance, [root.Path]);

        var keyResponse = await capability.ExecuteAsync(Request(keyPath));
        Assert.False(keyResponse.Ok);
        Assert.Contains("private key material", keyResponse.Error, StringComparison.OrdinalIgnoreCase);

        var contentResponse = await capability.ExecuteAsync(Request(contentPath));
        Assert.False(contentResponse.Ok);
        Assert.Contains("private key material", contentResponse.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FileRead_EnforcesMaxBytesAndRejectsUnknownArguments()
    {
        using var root = new TemporaryDirectory();
        var path = Path.Combine(root.Path, "sample.bin");
        await File.WriteAllBytesAsync(path, new byte[32]);
        var capability = new HostCapability(NullLogger.Instance, [root.Path]);

        var bounded = await capability.ExecuteAsync(Request(path, maxBytes: 8));
        Assert.False(bounded.Ok);
        Assert.Contains("exceeds maxBytes", bounded.Error, StringComparison.OrdinalIgnoreCase);

        var args = JsonSerializer.SerializeToElement(new { path, extra = true });
        var unknown = await capability.ExecuteAsync(new NodeInvokeRequest
        {
            Id = "file-read-extra",
            Command = "file.read",
            Args = args
        });
        Assert.False(unknown.Ok);
        Assert.Contains("unsupported file.read argument", unknown.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void McpRequest_AutoAuth_IsLimitedToConfiguredLoopbackPort()
    {
        Assert.True(HostCapability.ShouldAutoAuthorizeLocalMcp(
            new Uri("http://127.0.0.1:8765/"),
            mcpMode: true,
            hasExplicitAuthorization: false,
            localMcpPort: 8765));

        Assert.True(HostCapability.ShouldAutoAuthorizeLocalMcp(
            new Uri("http://[::1]:8765/"),
            mcpMode: true,
            hasExplicitAuthorization: false,
            localMcpPort: 8765));

        Assert.False(HostCapability.ShouldAutoAuthorizeLocalMcp(
            new Uri("http://127.0.0.1:18791/"),
            mcpMode: true,
            hasExplicitAuthorization: false,
            localMcpPort: 8765));

        Assert.False(HostCapability.ShouldAutoAuthorizeLocalMcp(
            new Uri("https://example.com:8765/"),
            mcpMode: true,
            hasExplicitAuthorization: false,
            localMcpPort: 8765));
    }

    [Fact]
    public void McpRequest_AutoAuth_PreservesExplicitAuthorizationAndHttpMode()
    {
        var localMcp = new Uri("http://127.0.0.1:8765/");

        Assert.False(HostCapability.ShouldAutoAuthorizeLocalMcp(
            localMcp,
            mcpMode: true,
            hasExplicitAuthorization: true,
            localMcpPort: 8765));

        Assert.False(HostCapability.ShouldAutoAuthorizeLocalMcp(
            localMcp,
            mcpMode: false,
            hasExplicitAuthorization: false,
            localMcpPort: 8765));
    }

    private static NodeInvokeRequest Request(string path, int? maxBytes = null)
    {
        var args = maxBytes.HasValue
            ? JsonSerializer.SerializeToElement(new { path, maxBytes = maxBytes.Value })
            : JsonSerializer.SerializeToElement(new { path });
        return new NodeInvokeRequest
        {
            Id = "file-read-test",
            Command = "file.read",
            Args = args
        };
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "openclaw-file-read-tests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch
            {
                // Test cleanup only.
            }
        }
    }
}
