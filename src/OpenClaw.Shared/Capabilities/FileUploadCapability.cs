using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace OpenClaw.Shared.Capabilities;

/// <summary>
/// Receives bounded binary files as independently base64-encoded chunks and
/// publishes them atomically beneath one approved root directory.
/// </summary>
public sealed class FileUploadCapability : NodeCapabilityBase, IDisposable
{
    public const long DefaultMaxFileBytes = 64L * 1024 * 1024;
    public const int MaxChunkBase64Chars = 500_000;

    private static readonly string[] CommandNames =
    [
        "files.upload.begin",
        "files.upload.append",
        "files.upload.commit",
        "files.upload.abort",
    ];

    private static readonly Regex Sha256Regex = new(
        "^[0-9a-fA-F]{64}$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(1);

    private readonly ConcurrentDictionary<string, UploadSession> _sessions =
        new(StringComparer.Ordinal);
    private readonly string _allowedRoot;
    private readonly string _stagingRoot;
    private readonly long _maxFileBytes;
    private bool _disposed;

    public FileUploadCapability(
        IOpenClawLogger logger,
        string allowedRoot,
        long maxFileBytes = DefaultMaxFileBytes)
        : base(logger)
    {
        if (string.IsNullOrWhiteSpace(allowedRoot))
            throw new ArgumentException("An upload root is required.", nameof(allowedRoot));
        if (maxFileBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxFileBytes));

        _allowedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(allowedRoot));
        _stagingRoot = Path.Combine(_allowedRoot, ".openclaw-uploads");
        _maxFileBytes = maxFileBytes;
    }

    public override string Category => "files";
    public override IReadOnlyList<string> Commands => CommandNames;

    public override Task<NodeInvokeResponse> ExecuteAsync(NodeInvokeRequest request)
        => ExecuteAsync(request, CancellationToken.None);

    public override async Task<NodeInvokeResponse> ExecuteAsync(
        NodeInvokeRequest request,
        CancellationToken cancellationToken)
    {
        if (_disposed)
            return Error("File upload capability is disposed.");

        try
        {
            return request.Command switch
            {
                "files.upload.begin" => await BeginAsync(request.Args, cancellationToken).ConfigureAwait(false),
                "files.upload.append" => await AppendAsync(request.Args, cancellationToken).ConfigureAwait(false),
                "files.upload.commit" => await CommitAsync(request.Args, cancellationToken).ConfigureAwait(false),
                "files.upload.abort" => await AbortAsync(request.Args, cancellationToken).ConfigureAwait(false),
                _ => Error($"Unknown command: {request.Command}"),
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return Error("cancelled");
        }
        catch (Exception ex)
        {
            Logger.Error($"{request.Command} failed", ex);
            return Error(ex.Message);
        }
    }

    private async Task<NodeInvokeResponse> BeginAsync(
        JsonElement args,
        CancellationToken cancellationToken)
    {
        CleanupExpiredSessions();

        var relativePath = GetStringArg(args, "relativePath")?.Trim();
        var expectedSha256 = GetStringArg(args, "expectedSha256")?.Trim();
        var expectedSize = GetInt64Arg(args, "expectedSize");
        var overwrite = GetBoolArg(args, "overwrite", false);

        if (string.IsNullOrWhiteSpace(relativePath))
            return Error("relativePath is required.");
        if (!Sha256Regex.IsMatch(expectedSha256 ?? string.Empty))
            return Error("expectedSha256 must be exactly 64 hexadecimal characters.");
        if (expectedSize is null or <= 0)
            return Error("expectedSize must be a positive integer.");
        if (expectedSize > _maxFileBytes)
            return Error($"expectedSize exceeds the {_maxFileBytes} byte upload limit.");

        var destinationPath = ResolveDestinationPath(relativePath);
        EnsureSafeDirectory(_allowedRoot, createIfMissing: true);
        EnsureSafeParentDirectory(destinationPath, createIfMissing: true);

        if (File.Exists(destinationPath) && !overwrite)
            return Error("Destination already exists and overwrite is false.");

        EnsureSafeDirectory(_stagingRoot, createIfMissing: true);

        var uploadId = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);
        var temporaryPath = Path.Combine(_stagingRoot, uploadId + ".partial");
        await using (var stream = new FileStream(
            temporaryPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 1,
            useAsync: true))
        {
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        var session = new UploadSession(
            uploadId,
            relativePath.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar),
            destinationPath,
            temporaryPath,
            expectedSize.Value,
            expectedSha256!.ToLowerInvariant(),
            overwrite,
            DateTimeOffset.UtcNow);

        if (!_sessions.TryAdd(uploadId, session))
        {
            DeleteFileBestEffort(temporaryPath);
            return Error("Could not allocate an upload session.");
        }

        Logger.Info(
            $"files.upload.begin id={uploadId} relativePath={session.RelativePath} expectedSize={session.ExpectedSize}");

        return Success(new
        {
            uploadId,
            relativePath = session.RelativePath,
            expectedSize = session.ExpectedSize,
            maxChunkBase64Chars = MaxChunkBase64Chars,
            expiresAt = session.CreatedAt.Add(SessionLifetime),
        });
    }

    private async Task<NodeInvokeResponse> AppendAsync(
        JsonElement args,
        CancellationToken cancellationToken)
    {
        var uploadId = GetStringArg(args, "uploadId")?.Trim();
        var sequence = GetInt64Arg(args, "sequence");
        var base64Chunk = GetStringArg(args, "base64Chunk");

        if (string.IsNullOrWhiteSpace(uploadId))
            return Error("uploadId is required.");
        if (sequence is null or < 0 || sequence > int.MaxValue)
            return Error("sequence must be a non-negative integer.");
        if (string.IsNullOrEmpty(base64Chunk))
            return Error("base64Chunk is required.");
        if (base64Chunk.Length > MaxChunkBase64Chars)
            return Error($"base64Chunk exceeds the {MaxChunkBase64Chars} character limit.");
        if (!_sessions.TryGetValue(uploadId, out var session))
            return Error("Unknown or expired uploadId.");

        await session.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (session.Completed)
                return Error("Upload session is already complete.");
            if (sequence.Value != session.NextSequence)
                return Error($"Expected sequence {session.NextSequence}, received {sequence.Value}.");

            byte[] bytes;
            try
            {
                bytes = Convert.FromBase64String(base64Chunk);
            }
            catch (FormatException)
            {
                return Error("base64Chunk is not valid base64.");
            }

            if (bytes.Length == 0)
                return Error("Decoded chunk is empty.");
            if (session.BytesReceived + bytes.LongLength > session.ExpectedSize)
                return Error("Decoded data exceeds expectedSize.");

            await using (var stream = new FileStream(
                session.TemporaryPath,
                FileMode.Append,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 128 * 1024,
                useAsync: true))
            {
                await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            session.BytesReceived += bytes.LongLength;
            session.NextSequence++;
            session.LastTouchedAt = DateTimeOffset.UtcNow;

            Logger.Debug(
                $"files.upload.append id={uploadId} sequence={sequence.Value} bytes={bytes.Length} total={session.BytesReceived}");

            return Success(new
            {
                uploadId,
                acceptedSequence = sequence.Value,
                nextSequence = session.NextSequence,
                bytesReceived = session.BytesReceived,
                expectedSize = session.ExpectedSize,
                complete = session.BytesReceived == session.ExpectedSize,
            });
        }
        finally
        {
            session.Gate.Release();
        }
    }

    private async Task<NodeInvokeResponse> CommitAsync(
        JsonElement args,
        CancellationToken cancellationToken)
    {
        var uploadId = GetStringArg(args, "uploadId")?.Trim();
        if (string.IsNullOrWhiteSpace(uploadId))
            return Error("uploadId is required.");
        if (!_sessions.TryGetValue(uploadId, out var session))
            return Error("Unknown or expired uploadId.");

        await session.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (session.Completed)
                return Error("Upload session is already complete.");
            if (session.BytesReceived != session.ExpectedSize)
            {
                return Error(
                    $"Upload is incomplete: received {session.BytesReceived} of {session.ExpectedSize} bytes.");
            }

            var actualHash = await ComputeSha256Async(session.TemporaryPath, cancellationToken)
                .ConfigureAwait(false);
            if (!string.Equals(actualHash, session.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                RemoveSessionAndTemporaryFile(session);
                session.Gate.Dispose();
                return Error(
                    $"SHA-256 mismatch: expected {session.ExpectedSha256}, actual {actualHash}.");
            }

            EnsureSafeParentDirectory(session.DestinationPath, createIfMissing: true);
            if (File.Exists(session.DestinationPath) && !session.Overwrite)
                return Error("Destination already exists and overwrite is false.");

            File.Move(session.TemporaryPath, session.DestinationPath, session.Overwrite);
            session.Completed = true;
            _sessions.TryRemove(uploadId, out _);

            var item = new FileInfo(session.DestinationPath);
            var uncPath = ToUncPath(session.DestinationPath);

            Logger.Info(
                $"files.upload.commit id={uploadId} relativePath={session.RelativePath} bytes={item.Length} sha256={actualHash}");

            session.Gate.Dispose();
            return Success(new
            {
                uploadId,
                path = session.DestinationPath,
                uncPath,
                relativePath = session.RelativePath,
                sizeBytes = item.Length,
                sha256 = actualHash,
            });
        }
        finally
        {
            if (!session.Completed)
                session.Gate.Release();
        }
    }

    private async Task<NodeInvokeResponse> AbortAsync(
        JsonElement args,
        CancellationToken cancellationToken)
    {
        var uploadId = GetStringArg(args, "uploadId")?.Trim();
        if (string.IsNullOrWhiteSpace(uploadId))
            return Error("uploadId is required.");
        if (!_sessions.TryGetValue(uploadId, out var session))
            return Success(new { uploadId, aborted = false, alreadyMissing = true });

        await session.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            RemoveSessionAndTemporaryFile(session);
            Logger.Info($"files.upload.abort id={uploadId} relativePath={session.RelativePath}");
            return Success(new { uploadId, aborted = true, alreadyMissing = false });
        }
        finally
        {
            session.Gate.Dispose();
        }
    }

    private string ResolveDestinationPath(string relativePath)
    {
        if (Path.IsPathRooted(relativePath) || relativePath.Contains(':'))
            throw new InvalidOperationException("relativePath must be relative to the approved upload root.");

        var normalized = relativePath.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
        var destination = Path.GetFullPath(Path.Combine(_allowedRoot, normalized));
        var rootPrefix = _allowedRoot + Path.DirectorySeparatorChar;

        if (!destination.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("relativePath escapes the approved upload root.");
        if (string.Equals(destination, _allowedRoot, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("relativePath must identify a file below the approved upload root.");
        if (destination.EndsWith(Path.DirectorySeparatorChar) ||
            destination.EndsWith(Path.AltDirectorySeparatorChar))
        {
            throw new InvalidOperationException("relativePath must identify a file, not a directory.");
        }

        return destination;
    }

    private void EnsureSafeParentDirectory(string destinationPath, bool createIfMissing)
    {
        var parent = Path.GetDirectoryName(destinationPath)
            ?? throw new InvalidOperationException("Destination has no parent directory.");
        EnsureSafeDirectory(parent, createIfMissing);
    }

    private void EnsureSafeDirectory(string directoryPath, bool createIfMissing)
    {
        var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directoryPath));
        var rootPrefix = _allowedRoot + Path.DirectorySeparatorChar;
        if (!string.Equals(fullPath, _allowedRoot, StringComparison.OrdinalIgnoreCase) &&
            !fullPath.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Directory escapes the approved upload root.");
        }

        if (!Directory.Exists(_allowedRoot))
        {
            if (!createIfMissing || !string.Equals(fullPath, _allowedRoot, StringComparison.OrdinalIgnoreCase))
                throw new DirectoryNotFoundException("Approved upload root does not exist.");
            Directory.CreateDirectory(_allowedRoot);
        }

        RejectReparsePoint(_allowedRoot);
        if (string.Equals(fullPath, _allowedRoot, StringComparison.OrdinalIgnoreCase))
            return;

        var relative = Path.GetRelativePath(_allowedRoot, fullPath);
        var current = _allowedRoot;
        foreach (var part in relative.Split(
            Path.DirectorySeparatorChar,
            StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            if (!Directory.Exists(current))
            {
                if (!createIfMissing)
                    throw new DirectoryNotFoundException($"Directory does not exist: {current}");
                Directory.CreateDirectory(current);
            }
            RejectReparsePoint(current);
        }
    }

    private static void RejectReparsePoint(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException($"Upload path contains a reparse point: {path}");
    }

    private static async Task<string> ComputeSha256Async(
        string path,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 128 * 1024,
            useAsync: true);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static long? GetInt64Arg(JsonElement args, string name)
    {
        if (args.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
            return null;
        if (!args.TryGetProperty(name, out var property) ||
            property.ValueKind != JsonValueKind.Number)
        {
            return null;
        }

        return property.TryGetInt64(out var value) ? value : null;
    }

    private static string ToUncPath(string path)
    {
        var root = Path.GetPathRoot(path);
        if (string.IsNullOrEmpty(root) || root.Length < 2 || root[1] != ':')
            return path;

        var share = char.ToUpperInvariant(root[0]).ToString();
        var relative = path[root.Length..]
            .TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return $"\\\\{Environment.MachineName}\\{share}\\{relative}";
    }

    private void CleanupExpiredSessions()
    {
        var cutoff = DateTimeOffset.UtcNow - SessionLifetime;
        foreach (var pair in _sessions)
        {
            if (pair.Value.LastTouchedAt >= cutoff)
                continue;
            if (!_sessions.TryRemove(pair.Key, out var expired))
                continue;

            DeleteFileBestEffort(expired.TemporaryPath);
            expired.Gate.Dispose();
            Logger.Info($"files.upload expired id={expired.UploadId} relativePath={expired.RelativePath}");
        }
    }

    private void RemoveSessionAndTemporaryFile(UploadSession session)
    {
        _sessions.TryRemove(session.UploadId, out _);
        DeleteFileBestEffort(session.TemporaryPath);
        session.Completed = true;
    }

    private static void DeleteFileBestEffort(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
            // Cleanup must not hide the primary upload result.
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;

        foreach (var pair in _sessions)
        {
            if (!_sessions.TryRemove(pair.Key, out var session))
                continue;
            DeleteFileBestEffort(session.TemporaryPath);
            session.Gate.Dispose();
        }
    }

    private sealed class UploadSession
    {
        public UploadSession(
            string uploadId,
            string relativePath,
            string destinationPath,
            string temporaryPath,
            long expectedSize,
            string expectedSha256,
            bool overwrite,
            DateTimeOffset createdAt)
        {
            UploadId = uploadId;
            RelativePath = relativePath;
            DestinationPath = destinationPath;
            TemporaryPath = temporaryPath;
            ExpectedSize = expectedSize;
            ExpectedSha256 = expectedSha256;
            Overwrite = overwrite;
            CreatedAt = createdAt;
            LastTouchedAt = createdAt;
        }

        public string UploadId { get; }
        public string RelativePath { get; }
        public string DestinationPath { get; }
        public string TemporaryPath { get; }
        public long ExpectedSize { get; }
        public string ExpectedSha256 { get; }
        public bool Overwrite { get; }
        public DateTimeOffset CreatedAt { get; }
        public DateTimeOffset LastTouchedAt { get; set; }
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public long BytesReceived { get; set; }
        public int NextSequence { get; set; }
        public bool Completed { get; set; }
    }
}
