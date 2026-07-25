using System.Security.Cryptography;
using System.Text.Json;
using OpenClaw.Shared.Capabilities;
using OpenClaw.TestSupport;

namespace OpenClaw.Shared.Tests;

public sealed class FileUploadCapabilityTests
{
    [Fact]
    public async Task UploadLifecycle_PublishesExactBytesAfterHashVerification()
    {
        using var root = new TempDirectory("file-upload-");
        using var capability = new FileUploadCapability(NullLogger.Instance, root.Path);
        var source = Enumerable.Range(0, 4097).Select(i => (byte)(i % 251)).ToArray();
        var expectedHash = Hash(source);

        var begin = await InvokeAsync(capability, "files.upload.begin", new
        {
            relativePath = "batch\\ORIGINALS\\01-original.png",
            expectedSize = source.LongLength,
            expectedSha256 = expectedHash,
        });

        Assert.True(begin.Ok, begin.Error);
        var uploadId = Payload(begin).GetProperty("uploadId").GetString()!;

        var first = source[..2048];
        var second = source[2048..];
        var append0 = await InvokeAsync(capability, "files.upload.append", new
        {
            uploadId,
            sequence = 0,
            base64Chunk = Convert.ToBase64String(first),
        });
        var append1 = await InvokeAsync(capability, "files.upload.append", new
        {
            uploadId,
            sequence = 1,
            base64Chunk = Convert.ToBase64String(second),
        });

        Assert.True(append0.Ok, append0.Error);
        Assert.True(append1.Ok, append1.Error);
        Assert.True(Payload(append1).GetProperty("complete").GetBoolean());

        var commit = await InvokeAsync(capability, "files.upload.commit", new { uploadId });

        Assert.True(commit.Ok, commit.Error);
        var destination = root.Combine("batch", "ORIGINALS", "01-original.png");
        Assert.Equal(source, await File.ReadAllBytesAsync(destination));
        Assert.Equal(expectedHash, Payload(commit).GetProperty("sha256").GetString());
        Assert.Equal(source.LongLength, Payload(commit).GetProperty("sizeBytes").GetInt64());
        Assert.Contains("01-original.png", Payload(commit).GetProperty("uncPath").GetString());
    }

    [Theory]
    [InlineData("..\\escape.bin")]
    [InlineData("C:\\outside.bin")]
    [InlineData("folder\\..\\..\\escape.bin")]
    public async Task Begin_RejectsPathsOutsideApprovedRoot(string relativePath)
    {
        using var root = new TempDirectory("file-upload-");
        using var capability = new FileUploadCapability(NullLogger.Instance, root.Path);

        var response = await InvokeAsync(capability, "files.upload.begin", new
        {
            relativePath,
            expectedSize = 1,
            expectedSha256 = Hash([1]),
        });

        Assert.False(response.Ok);
        Assert.Contains("root", response.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Append_RequiresStrictlyIncreasingSequenceNumbers()
    {
        using var root = new TempDirectory("file-upload-");
        using var capability = new FileUploadCapability(NullLogger.Instance, root.Path);
        var source = new byte[] { 1, 2, 3 };
        var begin = await InvokeAsync(capability, "files.upload.begin", new
        {
            relativePath = "sequence.bin",
            expectedSize = source.LongLength,
            expectedSha256 = Hash(source),
        });
        var uploadId = Payload(begin).GetProperty("uploadId").GetString()!;

        var response = await InvokeAsync(capability, "files.upload.append", new
        {
            uploadId,
            sequence = 1,
            base64Chunk = Convert.ToBase64String(source),
        });

        Assert.False(response.Ok);
        Assert.Contains("Expected sequence 0", response.Error);
        await InvokeAsync(capability, "files.upload.abort", new { uploadId });
    }

    [Fact]
    public async Task Commit_DeletesTemporaryFileWhenHashDoesNotMatch()
    {
        using var root = new TempDirectory("file-upload-");
        using var capability = new FileUploadCapability(NullLogger.Instance, root.Path);
        var source = new byte[] { 10, 20, 30, 40 };
        var begin = await InvokeAsync(capability, "files.upload.begin", new
        {
            relativePath = "bad-hash.bin",
            expectedSize = source.LongLength,
            expectedSha256 = new string('0', 64),
        });
        var uploadId = Payload(begin).GetProperty("uploadId").GetString()!;
        await InvokeAsync(capability, "files.upload.append", new
        {
            uploadId,
            sequence = 0,
            base64Chunk = Convert.ToBase64String(source),
        });

        var commit = await InvokeAsync(capability, "files.upload.commit", new { uploadId });

        Assert.False(commit.Ok);
        Assert.Contains("SHA-256 mismatch", commit.Error);
        Assert.False(File.Exists(root.Combine("bad-hash.bin")));
        Assert.False(File.Exists(root.Combine(".openclaw-uploads", uploadId + ".partial")));
    }

    [Fact]
    public async Task Begin_RequiresExplicitOverwriteForExistingDestination()
    {
        using var root = new TempDirectory("file-upload-");
        var destination = root.Combine("existing.bin");
        await File.WriteAllBytesAsync(destination, [9]);
        using var capability = new FileUploadCapability(NullLogger.Instance, root.Path);
        var source = new byte[] { 1 };

        var response = await InvokeAsync(capability, "files.upload.begin", new
        {
            relativePath = "existing.bin",
            expectedSize = source.LongLength,
            expectedSha256 = Hash(source),
        });

        Assert.False(response.Ok);
        Assert.Contains("overwrite is false", response.Error);
        Assert.Equal(new byte[] { 9 }, await File.ReadAllBytesAsync(destination));
    }

    [Fact]
    public async Task Abort_RemovesStagedUploadWithoutPublishing()
    {
        using var root = new TempDirectory("file-upload-");
        using var capability = new FileUploadCapability(NullLogger.Instance, root.Path);
        var source = new byte[] { 1, 2, 3 };
        var begin = await InvokeAsync(capability, "files.upload.begin", new
        {
            relativePath = "aborted.bin",
            expectedSize = source.LongLength,
            expectedSha256 = Hash(source),
        });
        var uploadId = Payload(begin).GetProperty("uploadId").GetString()!;
        await InvokeAsync(capability, "files.upload.append", new
        {
            uploadId,
            sequence = 0,
            base64Chunk = Convert.ToBase64String(source),
        });

        var abort = await InvokeAsync(capability, "files.upload.abort", new { uploadId });

        Assert.True(abort.Ok, abort.Error);
        Assert.True(Payload(abort).GetProperty("aborted").GetBoolean());
        Assert.False(File.Exists(root.Combine("aborted.bin")));
        Assert.False(File.Exists(root.Combine(".openclaw-uploads", uploadId + ".partial")));
    }

    private static async Task<NodeInvokeResponse> InvokeAsync(
        FileUploadCapability capability,
        string command,
        object args)
        => await capability.ExecuteAsync(new NodeInvokeRequest
        {
            Id = Guid.NewGuid().ToString("N"),
            Command = command,
            Args = JsonSerializer.SerializeToElement(args),
        });

    private static JsonElement Payload(NodeInvokeResponse response)
        => JsonSerializer.SerializeToElement(response.Payload);

    private static string Hash(byte[] bytes)
        => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
