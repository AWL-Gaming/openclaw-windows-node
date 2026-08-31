using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace OpenClaw.Shared.Capabilities;

/// <summary>
/// Structured host-control surface for private MCP/fabric callers.  It exists to
/// avoid fragile shell quoting for ordinary filesystem/process/service/archive,
/// localhost HTTP/MCP, Git, and process-scoped window operations.
/// </summary>
public sealed class HostCapability : NodeCapabilityBase
{
    private static readonly string[] s_commands = ["host.describe", "host.invoke", "file.read"];
    private static readonly string[] s_operations =
    [
        "file.stat", "file.list", "file.write", "file.append", "file.mkdir",
        "file.move", "file.copy", "file.delete", "file.hash",
        "process.list", "process.status", "process.spawn", "process.terminate",
        "service.list", "service.status", "service.start", "service.stop", "service.restart",
        "archive.pack", "archive.unpack",
        "git.run",
        "http.request", "mcp.request",
        "window.list", "window.inspect", "window.input", "window.capture"
    ];

    private const int DefaultTimeoutMs = 30_000;
    private const int MaxTimeoutMs = 600_000;
    private const int MaxTextWriteBytes = 32 * 1024 * 1024;
    private const int MaxHttpResponseBytes = 16 * 1024 * 1024;
    private const int MaxWindowCaptureBytes = 64 * 1024 * 1024;
    private const int MaxWindowCapturePixels = 12_000_000;
    private const int DefaultFileReadMaxBytes = 512 * 1024;
    private const int HardFileReadMaxBytes = 1024 * 1024;
    private const string FileReadRootsEnvironmentVariable = "AWL_MCP_NODE_FILE_READ_ROOTS";
    private static readonly HttpClient s_http = new();
    private readonly string[] _fileReadApprovedRoots;
    private readonly string[] _fileReadDeniedRoots;

    public event Func<WindowCaptureArgs, CancellationToken, Task<WindowCaptureResult>>? WindowCaptureRequested;

    public HostCapability(IOpenClawLogger logger, IEnumerable<string>? fileReadRoots = null) : base(logger)
    {
        _fileReadApprovedRoots = ResolveFileReadApprovedRoots(fileReadRoots);
        _fileReadDeniedRoots = ResolveFileReadDeniedRoots();
    }

    public override string Category => "host";
    public override IReadOnlyList<string> Commands => s_commands;

    public override Task<NodeInvokeResponse> ExecuteAsync(NodeInvokeRequest request)
        => ExecuteAsync(request, CancellationToken.None);

    public override async Task<NodeInvokeResponse> ExecuteAsync(
        NodeInvokeRequest request,
        CancellationToken cancellationToken)
    {
        if (string.Equals(request.Command, "host.describe", StringComparison.OrdinalIgnoreCase))
        {
            return Success(new
            {
                platform = OperatingSystem.IsWindows() ? "windows" : "unknown",
                operations = s_operations,
                guarantees = new
                {
                    windowInput = "PostMessage to an exact HWND owned by the requested PID; never SendInput and never global cursor/keyboard injection",
                    windowCapture = "One bounded Windows.Graphics.Capture frame for an exact HWND; capture runs outside the target process, never injects a capture hook, and has hard timeout/size limits",
                    httpDefault = "loopback/private/link-local targets only unless allowPublic=true",
                    fileWrites = "atomic replace supported through atomic=true; parent directories are never created unless createParents=true"
                }
            });
        }

        if (string.Equals(request.Command, "file.read", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                return FileRead(request.Args);
            }
            catch (Exception ex)
            {
                Logger.Warn($"file.read failed: {ex.Message}");
                return Error(ex.Message);
            }
        }

        if (!string.Equals(request.Command, "host.invoke", StringComparison.OrdinalIgnoreCase))
            return Error($" Unknown command: {request.Command}");

        var operation = GetStringArg(request.Args, "operation")?.Trim();
        if (string.IsNullOrWhiteSpace(operation))
            return Error("Missing operation parameter");

        try
        {
            return operation.ToLowerInvariant() switch
            {
                "file.stat" => FileStat(request.Args),
                "file.list" => FileList(request.Args),
                "file.write" => FileWrite(request.Args, append: false),
                "file.append" => FileWrite(request.Args, append: true),
                "file.mkdir" => FileMkdir(request.Args),
                "file.move" => FileMove(request.Args),
                "file.copy" => FileCopy(request.Args),
                "file.delete" => FileDelete(request.Args),
                "file.hash" => await FileHashAsync(request.Args, cancellationToken),
                "process.list" => ProcessList(request.Args),
                "process.status" => ProcessStatus(request.Args),
                "process.spawn" => await ProcessSpawnAsync(request.Args, cancellationToken),
                "process.terminate" => ProcessTerminate(request.Args),
                "service.list" => await ServiceCommandAsync("list", request.Args, cancellationToken),
                "service.status" => await ServiceCommandAsync("status", request.Args, cancellationToken),
                "service.start" => await ServiceCommandAsync("start", request.Args, cancellationToken),
                "service.stop" => await ServiceCommandAsync("stop", request.Args, cancellationToken),
                "service.restart" => await ServiceCommandAsync("restart", request.Args, cancellationToken),
                "archive.pack" => ArchivePack(request.Args),
                "archive.unpack" => ArchiveUnpack(request.Args),
                "git.run" => await GitRunAsync(request.Args, cancellationToken),
                "http.request" => await HttpRequestAsync(request.Args, cancellationToken, mcpMode: false),
                "mcp.request" => await HttpRequestAsync(request.Args, cancellationToken, mcpMode: true),
                "window.list" => WindowList(request.Args),
                "window.inspect" => WindowInspect(request.Args),
                "window.input" => WindowInput(request.Args),
                "window.capture" => await WindowCaptureAsync(request.Args, cancellationToken),
                _ => Error($" Unsupported host operation: {operation}")
            };
        }
        catch (OperationCanceledException)
        {
            return Error("Host operation cancelled or timed out");
        }
        catch (Exception ex)
        {
            Logger.Warn($"host.invoke {operation} failed: {ex.Message}");
            return Error(ex.Message);
        }
    }

    private NodeInvokeResponse FileRead(JsonElement args)
    {
        if (args.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException("file.read arguments must be an object");

        foreach (var property in args.EnumerateObject())
        {
            if (!string.Equals(property.Name, "path", StringComparison.Ordinal) &&
                !string.Equals(property.Name, "maxBytes", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("unsupported file.read argument");
            }
        }

        if (_fileReadApprovedRoots.Length == 0)
            throw new InvalidOperationException("file.read is disabled because no approved read roots are configured");

        var requestedPath = GetStringArg(args, "path");
        if (string.IsNullOrEmpty(requestedPath))
            throw new InvalidOperationException("missing required string: path");

        ValidateFileReadLexicalPath(requestedPath);

        var effectiveMax = DefaultFileReadMaxBytes;
        if (args.TryGetProperty("maxBytes", out var maxBytesElement))
        {
            if (maxBytesElement.ValueKind != JsonValueKind.Number ||
                !maxBytesElement.TryGetInt64(out var requestedMax) ||
                requestedMax <= 0)
            {
                throw new InvalidOperationException("maxBytes must be a positive integer");
            }
            effectiveMax = (int)Math.Min(requestedMax, HardFileReadMaxBytes);
        }

        var lexicalPath = NormalizeFileReadPath(requestedPath);
        EnsureFileReadPathAllowed(lexicalPath, "requested file");
        RejectPrivateKeyPath(lexicalPath);

        using var stream = new FileStream(
            lexicalPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);

        var finalPath = GetFinalPathFromHandle(stream.SafeFileHandle.DangerousGetHandle());
        EnsureFileReadPathAllowed(finalPath, "resolved file");
        RejectPrivateKeyPath(finalPath);

        if (stream.Length > effectiveMax)
            throw new InvalidOperationException("requested file exceeds maxBytes");

        using var output = new MemoryStream(Math.Min(effectiveMax, 64 * 1024));
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read <= 0) break;
            if (output.Length + read > effectiveMax)
                throw new InvalidOperationException("requested file exceeded maxBytes while being read");
            output.Write(buffer, 0, read);
        }

        var bytes = output.ToArray();
        RejectPrivateKeyContents(bytes);

        var mimeType = InferFileReadMime(bytes);
        var sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var pathHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(requestedPath))).ToLowerInvariant();
        Logger.Info($"file.read completed pathHash={pathHash} sizeBytes={bytes.Length} mimeType={mimeType}");

        return Success(new
        {
            fileName = Path.GetFileName(finalPath),
            sizeBytes = bytes.Length,
            mimeType,
            sha256,
            base64 = Convert.ToBase64String(bytes)
        });
    }

    private static string[] ResolveFileReadApprovedRoots(IEnumerable<string>? explicitRoots)
    {
        IEnumerable<string> candidates;
        if (explicitRoots != null)
        {
            candidates = explicitRoots;
        }
        else
        {
            var configured = Environment.GetEnvironmentVariable(FileReadRootsEnvironmentVariable);
            if (!string.IsNullOrWhiteSpace(configured))
            {
                candidates = configured.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            }
            else
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                candidates = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
                    Path.Combine(userProfile, "Downloads"),
                    @"D:\AWL-Development"
                };
            }
        }

        return candidates
            .Where(path => !string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
            .Select(NormalizeFileReadPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string[] ResolveFileReadDeniedRoots()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var applicationData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var commonApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        return new[]
        {
            Path.Combine(userProfile, ".openclaw"),
            Path.Combine(applicationData, "OpenClawTray"),
            Path.Combine(localApplicationData, "OpenClawTray"),
            Path.Combine(commonApplicationData, "AWL", "secrets"),
            AppContext.BaseDirectory
        }
        .Where(path => !string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
        .Select(NormalizeFileReadPath)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();
    }

    private void EnsureFileReadPathAllowed(string path, string label)
    {
        if (!_fileReadApprovedRoots.Any(root => IsFileReadPathWithin(path, root)))
            throw new InvalidOperationException($"{label} is outside approved read roots");
        if (_fileReadDeniedRoots.Any(root => IsFileReadPathWithin(path, root)))
            throw new InvalidOperationException($"{label} is in a protected node/control location");
    }

    private static void ValidateFileReadLexicalPath(string path)
    {
        if (string.IsNullOrEmpty(path) || !string.Equals(path, path.Trim(), StringComparison.Ordinal) || path.Contains('\0'))
            throw new InvalidOperationException("path must be an exact absolute Windows local path");
        if (path.Contains('%'))
            throw new InvalidOperationException("environment-variable syntax is not allowed");
        if (path.Contains('*') || path.Contains('?'))
            throw new InvalidOperationException("wildcards are not allowed");
        if (path.Contains("://", StringComparison.Ordinal))
            throw new InvalidOperationException("URLs are not allowed");
        if (path.StartsWith("\\\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
            throw new InvalidOperationException("UNC, device, and network paths are not allowed");
        if (path.Length < 3 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || (path[2] != '\\' && path[2] != '/'))
            throw new InvalidOperationException("path must be an absolute local drive path");
        if (path.AsSpan(2).IndexOf(':') >= 0)
            throw new InvalidOperationException("alternate data streams are not allowed");

        foreach (var segment in path[3..].Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment is "." or "..")
                throw new InvalidOperationException("dot path components are not allowed");
            if (segment.EndsWith(' ') || segment.EndsWith('.'))
                throw new InvalidOperationException("ambiguous Windows path components are not allowed");
        }
    }

    private static string NormalizeFileReadPath(string path)
    {
        var normalized = Path.GetFullPath(path).Replace('/', '\\').TrimEnd('\\');
        return normalized.Length == 2 && normalized[1] == ':' ? normalized + "\\" : normalized;
    }

    private static bool IsFileReadPathWithin(string candidate, string root)
    {
        var candidateKey = candidate.TrimEnd('\\');
        var rootKey = root.TrimEnd('\\');
        return string.Equals(candidateKey, rootKey, StringComparison.OrdinalIgnoreCase) ||
            candidateKey.StartsWith(rootKey + "\\", StringComparison.OrdinalIgnoreCase);
    }

    private static string GetFinalPathFromHandle(IntPtr handle)
    {
        var buffer = new StringBuilder(32_768);
        var written = Native.GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
        if (written == 0 || written >= buffer.Capacity)
            throw new InvalidOperationException("opened file final path could not be resolved");

        var path = buffer.ToString();
        if (path.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("resolved path is not a local drive path");
        if (path.StartsWith("\\\\?\\", StringComparison.Ordinal))
            path = path[4..];

        ValidateFileReadLexicalPath(path);
        return NormalizeFileReadPath(path);
    }

    private static void RejectPrivateKeyPath(string path)
    {
        var fileName = Path.GetFileName(path).ToLowerInvariant();
        var extension = Path.GetExtension(path).TrimStart('.').ToLowerInvariant();
        if (fileName is "id_rsa" or "id_dsa" or "id_ecdsa" or "id_ed25519" ||
            extension is "key" or "pfx" or "p12" or "ppk" or "pk8")
        {
            throw new InvalidOperationException("private key material is protected");
        }
    }

    private static void RejectPrivateKeyContents(byte[] bytes)
    {
        var content = Encoding.ASCII.GetString(bytes);
        string[] markers =
        [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "PuTTY-User-Key-File-"
        ];
        if (markers.Any(marker => content.Contains(marker, StringComparison.Ordinal)))
            throw new InvalidOperationException("private key material is protected");
    }

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly UnicodeEncoding StrictUtf16Le = new(false, false, true);
    private static readonly UnicodeEncoding StrictUtf16Be = new(true, false, true);

    private static string InferFileReadMime(byte[] bytes)
    {
        ReadOnlySpan<byte> png = [0x89, (byte)'P', (byte)'N', (byte)'G', 0x0D, 0x0A, 0x1A, 0x0A];
        ReadOnlySpan<byte> jpeg = [0xFF, 0xD8, 0xFF];
        ReadOnlySpan<byte> utf16LeBom = [0xFF, 0xFE];
        ReadOnlySpan<byte> utf16BeBom = [0xFE, 0xFF];
        ReadOnlySpan<byte> utf8Bom = [0xEF, 0xBB, 0xBF];
        if (bytes.AsSpan().StartsWith(png))
            return "image/png";
        if (bytes.AsSpan().StartsWith(jpeg))
            return "image/jpeg";

        if (bytes.AsSpan().StartsWith(utf16LeBom) &&
            TryDecodeSafeText(StrictUtf16Le, bytes.AsSpan(2)))
        {
            return "text/plain; charset=utf-16le";
        }
        if (bytes.AsSpan().StartsWith(utf16BeBom) &&
            TryDecodeSafeText(StrictUtf16Be, bytes.AsSpan(2)))
        {
            return "text/plain; charset=utf-16be";
        }

        var utf8 = bytes.AsSpan();
        if (utf8.StartsWith(utf8Bom))
            utf8 = utf8[3..];
        if (TryDecodeSafeText(StrictUtf8, utf8))
            return "text/plain; charset=utf-8";

        return "application/octet-stream";
    }

    private static bool TryDecodeSafeText(Encoding encoding, ReadOnlySpan<byte> bytes)
    {
        try
        {
            return IsSafeText(encoding.GetString(bytes));
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    private static bool IsSafeText(string text)
    {
        foreach (var value in text)
        {
            if (value is '\t' or '\r' or '\n')
                continue;
            if (char.IsControl(value))
                return false;
        }
        return true;
    }

    private NodeInvokeResponse FileStat(JsonElement args)
    {
        var path = RequirePath(args, "path");
        if (File.Exists(path))
        {
            var info = new FileInfo(path);
            return Success(new
            {
                path = info.FullName,
                type = "file",
                info.Length,
                info.CreationTimeUtc,
                info.LastWriteTimeUtc,
                attributes = info.Attributes.ToString()
            });
        }
        if (Directory.Exists(path))
        {
            var info = new DirectoryInfo(path);
            return Success(new
            {
                path = info.FullName,
                type = "directory",
                info.CreationTimeUtc,
                info.LastWriteTimeUtc,
                attributes = info.Attributes.ToString()
            });
        }
        return Error($" Path does not exist: {path}");
    }

    private NodeInvokeResponse FileList(JsonElement args)
    {
        var path = RequirePath(args, "path");
        if (!Directory.Exists(path))
            return Error($" Directory does not exist: {path}");

        var pattern = GetStringArg(args, "pattern", "*") ?? "*";
        var recursive = GetBoolArg(args, "recursive", false);
        var maxEntries = Math.Clamp(GetIntArg(args, "maxEntries", 1000), 1, 10_000);
        var option = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        var entries = Directory.EnumerateFileSystemEntries(path, pattern, option)
            .Take(maxEntries)
            .Select(p =>
            {
                var isDir = Directory.Exists(p);
                return new
                {
                    path = Path.GetFullPath(p),
                    name = Path.GetFileName(p),
                    type = isDir ? "directory" : "file",
                    size = isDir ? (long?)null : new FileInfo(p).Length,
                    lastWriteTimeUtc = isDir ? Directory.GetLastWriteTimeUtc(p) : File.GetLastWriteTimeUtc(p)
                };
            })
            .ToArray();
        return Success(new { path = Path.GetFullPath(path), entries, truncated = entries.Length >= maxEntries });
    }

    private NodeInvokeResponse FileWrite(JsonElement args, bool append)
    {
        var path = RequirePath(args, "path");
        var createParents = GetBoolArg(args, "createParents", false);
        var atomic = !append && GetBoolArg(args, "atomic", true);
        var encodingName = GetStringArg(args, "encoding", "utf8") ?? "utf8";
        byte[] bytes;

        if (args.TryGetProperty("base64", out var base64) && base64.ValueKind == JsonValueKind.String)
            bytes = Convert.FromBase64String(base64.GetString() ?? string.Empty);
        else
        {
            var text = GetStringArg(args, "text") ?? string.Empty;
            var encoding = encodingName.ToLowerInvariant() switch
            {
                "utf8" or "utf-8" => new UTF8Encoding(false),
                "utf16" or "utf-16" => Encoding.Unicode,
                "ascii" => Encoding.ASCII,
                _ => throw new InvalidOperationException($" Unsupported encoding: {encodingName}")
            };
            bytes = encoding.GetBytes(text);
        }

        if (bytes.Length > MaxTextWriteBytes)
            return Error(" Write exceeds {MaxTextWriteBytes} bytes");

        var full = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(full);
        if (!string.IsNullOrEmpty(parent) && !Directory.Exists(parent))
        {
            if (!createParents)
                return Error(" Parent directory does not exist: {parent}");
            Directory.CreateDirectory(parent);
        }

        if (append)
        {
            using var stream = new FileStream(full, FileMode.Append, FileAccess.Write, FileShare.Read);
            stream.Write(bytes);
        }
        else if (atomic)
        {
            var temp = full + ".awl-partial-" + Guid.NewGuid().ToString("N");
            try
            {
                File.WriteAllBytes(temp, bytes);
                if (File.Exists(full))
                    File.Move(temp, full, overwrite: true);
                else
                    File.Move(temp, full);
            }
            finally
            {
                try { if (File.Exists(temp)) File.Delete(temp); } catch { }
            }
        }
        else
        {
            File.WriteAllBytes(full, bytes);
        }

        return Success(new { path = full, bytes = bytes.Length, append, atomic });
    }

    private NodeInvokeResponse FileMkdir(JsonElement args)
    {
        var path = RequirePath(args, "path");
        var info = Directory.CreateDirectory(path);
        return Success(new { path = info.FullName, created = true });
    }

    private NodeInvokeResponse FileMove(JsonElement args)
    {
        var source = RequirePath(args, "source");
        var destination = RequirePath(args, "destination");
        var overwrite = GetBoolArg(args, "overwrite", false);
        if (File.Exists(source))
            File.Move(source, destination, overwrite);
        else if (Directory.Exists(source))
        {
            if (overwrite && Directory.Exists(destination))
                Directory.Delete(destination, recursive: true);
            Directory.Move(source, destination);
        }
        else
            return Error($" Source does not exist: {source}");
        return Success(new { source = Path.GetFullPath(source), destination = Path.GetFullPath(destination) });
    }

    private NodeInvokeResponse FileCopy(JsonElement args)
    {
        var source = RequirePath(args, "source");
        var destination = RequirePath(args, "destination");
        var overwrite = GetBoolArg(args, "overwrite", false);
        if (!File.Exists(source))
            return Error("file.copy currently accepts files only");
        File.Copy(source, destination, overwrite);
        return Success(new { source = Path.GetFullPath(source), destination = Path.GetFullPath(destination) });
    }

    private NodeInvokeResponse FileDelete(JsonElement args)
    {
        var path = RequirePath(args, "path");
        var recursive = GetBoolArg(args, "recursive", false);
        if (File.Exists(path))
            File.Delete(path);
        else if (Directory.Exists(path))
            Directory.Delete(path, recursive);
        else
            return Error($" Path does not exist: {path}");
        return Success(new { path = Path.GetFullPath(path), deleted = true, recursive });
    }

    private async Task<NodeInvokeResponse> FileHashAsync(JsonElement args, CancellationToken cancellationToken)
    {
        var path = RequirePath(args, "path");
        if (!File.Exists(path))
            return Error("File does not exist: {path}");
        var algorithm = (GetStringArg(args, "algorithm", "sha256") ?? "sha256").ToLowerInvariant();
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1024 * 1024, true);
        byte[] hash = algorithm switch
        {
            "sha256" => await SHA256.HashDataAsync(stream, cancellationToken),
            "sha512" => await SHA512.HashDataAsync(stream, cancellationToken),
            _ => throw new InvalidOperationException("algorithm must be sha256 or sha512")
        };
        return Success(new { path = Path.GetFullPath(path), algorithm, hash = Convert.ToHexString(hash).ToLowerInvariant() });
    }

    private NodeInvokeResponse ProcessList(JsonElement args)
    {
        var name = GetStringArg(args, "name");
        var maxEntries = Math.Clamp(GetIntArg(args, "maxEntries", 500), 1, 5000);
        var processes = Process.GetProcesses()
            .Where(p => string.IsNullOrWhiteSpace(name) || p.ProcessName.Contains(name, StringComparison.OrdinalIgnoreCase))
            .OrderBy(p => p.Id)
            .Take(maxEntries)
            .Select(ProcessView)
            .ToArray();
        return Success(new { processes });
    }

    private NodeInvokeResponse ProcessStatus(JsonElement args)
    {
        var pid = GetIntArg(args, "pid", 0);
        if (pid <= 0) return Error("pid must be greater than zero");
        using var process = Process.GetProcessById(pid);
        return Success(ProcessView(process));
    }

    private async Task<NodeInvokeResponse> ProcessSpawnAsync(JsonElement args, CancellationToken cancellationToken)
    {
        var fileName = GetStringArg(args, "fileName") ?? GetStringArg(args, "command");
        if (string.IsNullOrWhiteSpace(fileName)) return Error("fileName or command is required");
        var argumentList = GetStringArrayArg(args, "args");
        var cwd = GetStringArg(args, "cwd");
        var wait = GetBoolArg(args, "wait", false);
        var timeoutMs = Math.Clamp(GetIntArg(args, "timeoutMs", DefaultTimeoutMs), 1, MaxTimeoutMs);

        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = string.IsNullOrWhiteSpace(cwd) ? Environment.CurrentDirectory : cwd,
            UseShellExecute = false,
            RedirectStandardOutput = wait,
            RedirectStandardError = wait,
            CreateNoWindow = true
        };
        foreach (var arg in argumentList) psi.ArgumentList.Add(arg);
        if (args.TryGetProperty("env", out var env) && env.ValueKind == JsonValueKind.Object)
            foreach (var item in env.EnumerateObject())
                psi.Environment[item.Name] = item.Value.ValueKind == JsonValueKind.String ? item.Value.GetString() ?? "" : item.Value.ToString();

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("Process failed to start");
        if (!wait)
            return Success(new { processId = process.Id, started = true });

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeoutMs);
        var stdoutTask = process.StandardOutput.ReadToEndAsync(cts.Token);
        var stderrTask = process.StandardError.ReadToEndAsync(cts.Token);
        await process.WaitForExitAsync(cts.Token);
        return Success(new
        {
            processId = process.Id,
            exitCode = process.ExitCode,
            stdout = await stdoutTask,
            stderr = await stderrTask
        });
    }

    private NodeInvokeResponse ProcessTerminate(JsonElement args)
    {
        var pid = GetIntArg(args, "pid", 0);
        if (pid <= 0 || pid == Environment.ProcessId)
            return Error("A different positive pid is required");
        var entireTree = GetBoolArg(args, "entireTree", false);
        using var process = Process.GetProcessById(pid);
        var view = ProcessView(process);
        process.Kill(entireTree);
        return Success(new { terminated = true, process = view, entireTree });
    }

    private async Task<NodeInvokeResponse> ServiceCommandAsync(
        string operation,
        JsonElement args,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return Error("service operations are currently implemented for Windows only");

        var name = GetStringArg(args, "name");
        if (operation != "list" && string.IsNullOrWhiteSpace(name))
            return Error("service name is required");

        var maxEntries = Math.Clamp(GetIntArg(args, "maxEntries", 200), 1, 1000);
        var filter = GetStringArg(args, "filter") ?? (operation == "list" ? name : null) ?? "";
        var encodedName = Convert.ToBase64String(Encoding.UTF8.GetBytes(name ?? ""));
        var encodedFilter = Convert.ToBase64String(Encoding.UTF8.GetBytes(filter));
        var decodePrefix =
            "$enc=[Text.Encoding]::UTF8;" +
            "$n=$enc.GetString([Convert]::FromBase64String('" + encodedName + "'));" +
            "$filter=$enc.GetString([Convert]::FromBase64String('" + encodedFilter + "'));";

        var script = operation switch
        {
            "list" => decodePrefix +
                "$items=Get-Service;" +
                "if(-not [string]::IsNullOrWhiteSpace($filter)){" +
                "$items=$items | Where-Object { $_.Name -like ('*'+$filter+'*') -or $_.DisplayName -like ('*'+$filter+'*') };" +
                "}" +
                "$result=@($items | Sort-Object Name | Select-Object -First " + maxEntries + " | Select-Object Name,DisplayName,Status,StartType);" +
                "$result | ConvertTo-Json -Compress",
            "status" => decodePrefix +
                "$s=Get-Service -Name $n -ErrorAction Stop;" +
                "$s | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress",
            "start" => decodePrefix +
                "Start-Service -Name $n -ErrorAction Stop;" +
                "$s=Get-Service -Name $n -ErrorAction Stop; $s.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(15));" +
                "$s.Refresh(); $s | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress",
            "stop" => decodePrefix +
                "Stop-Service -Name $n -ErrorAction Stop;" +
                "$s=Get-Service -Name $n -ErrorAction Stop; $s.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(15));" +
                "$s.Refresh(); $s | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress",
            "restart" => decodePrefix +
                "Restart-Service -Name $n -ErrorAction Stop;" +
                "$s=Get-Service -Name $n -ErrorAction Stop; $s.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(20));" +
                "$s.Refresh(); $s | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress",
            _ => throw new InvalidOperationException("unsupported service operation")
        };
        return await RunJsonProcessAsync(
            "powershell.exe",
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
            null,
            DefaultTimeoutMs,
            cancellationToken);
    }

    private NodeInvokeResponse ArchivePack(JsonElement args)
    {
        var source = RequirePath(args, "source");
        var destination = RequirePath(args, "destination");
        var overwrite = GetBoolArg(args, "overwrite", false);
        if (!Directory.Exists(source))
            return Error("archive.pack source must be a directory");
        if (File.Exists(destination))
        {
            if (!overwrite) return Error($" Destination exists: {destination}");
            File.Delete(destination);
        }
        ZipFile.CreateFromDirectory(source, destination, CompressionLevel.Optimal, includeBaseDirectory: false);
        return Success(new { source = Path.GetFullPath(source), destination = Path.GetFullPath(destination) });
    }

    private NodeInvokeResponse ArchiveUnpack(JsonElement args)
    {
        var source = RequirePath(args, "source");
        var destination = RequirePath(args, "destination");
        var overwrite = GetBoolArg(args, "overwrite", false);
        if (!File.Exists(source))
            return Error($" Archive does not exist: {source}");
        Directory.CreateDirectory(destination);
        ZipFile.ExtractToDirectory(source, destination, overwrite);
        return Success(new { source = Path.GetFullPath(source), destination = Path.GetFullPath(destination) });
    }

    private async Task<NodeInvokeResponse> GitRunAsync(JsonElement args, CancellationToken cancellationToken)
    {
        var cwd = RequirePath(args, "cwd");
        if (!Directory.Exists(cwd))
            return Error($" Git working directory does not exist: {cwd}");
        var gitArgs = GetStringArrayArg(args, "args");
        if (gitArgs.Length == 0)
            return Error("git.run requires args");
        var timeoutMs = Math.Clamp(GetIntArg(args, "timeoutMs", DefaultTimeoutMs), 1, MaxTimeoutMs);
        return await RunProcessAsync("git.exe", gitArgs, cwd, timeoutMs, cancellationToken);
    }

    private async Task<NodeInvokeResponse> HttpRequestAsync(
        JsonElement args,
        CancellationToken cancellationToken,
        bool mcpMode)
    {
        var rawUrl = GetStringArg(args, "url");
        if (string.IsNullOrWhiteSpace(rawUrl) || !Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri))
            return Error("A valid absolute url is required");
        var allowPublic = GetBoolArg(args, "allowPublic", false);
        if (!allowPublic && !IsPrivateOrLoopback(uri))
            return Error("Public HTTP targets require allowPublic=true");

        var method = mcpMode ? "POST" : (GetStringArg(args, "method", "GET") ?? "GET").ToUpperInvariant();
        var timeoutMs = Math.Clamp(GetIntArg(args, "timeoutMs", DefaultTimeoutMs), 1, MaxTimeoutMs);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeoutMs);
        using var request = new HttpRequestMessage(new HttpMethod(method), uri);

        var hasExplicitAuthorization = false;
        if (args.TryGetProperty("headers", out var headers) && headers.ValueKind == JsonValueKind.Object)
        {
            foreach (var item in headers.EnumerateObject())
            {
                if (string.Equals(item.Name, "Authorization", StringComparison.OrdinalIgnoreCase))
                    hasExplicitAuthorization = true;
                request.Headers.TryAddWithoutValidation(item.Name, item.Value.GetString() ?? item.Value.ToString());
            }
        }

        if (ShouldAutoAuthorizeLocalMcp(uri, mcpMode, hasExplicitAuthorization, ResolveLocalMcpPort()))
        {
            var tokenPath = OpenClawAppIdentity.ResolveMcpTokenPath(Environment.GetEnvironmentVariable);
            var token = OpenClaw.Shared.Mcp.McpAuthToken.TryLoad(tokenPath);
            if (string.IsNullOrWhiteSpace(token))
                return Error("Local MCP bearer token is unavailable; ensure the local MCP server is enabled and its token file exists");
            request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
        }

        if (mcpMode)
        {
            JsonElement rpc;
            if (args.TryGetProperty("rpc", out var rpcElement))
                rpc = rpcElement;
            else
                return Error("mcp.request requires rpc");
            request.Content = new StringContent(rpc.GetRawText(), Encoding.UTF8, "application/json");
        }
        else if (args.TryGetProperty("body", out var body))
        {
            var mediaType = GetStringArg(args, "contentType", "application/json") ?? "application/json";
            var bodyText = body.ValueKind == JsonValueKind.String ? body.GetString() ?? "" : body.GetRawText();
            request.Content = new StringContent(bodyText, Encoding.UTF8, mediaType);
        }

        using var response = await s_http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);
        await using var stream = await response.Content.ReadAsStreamAsync(cts.Token);
        using var memory = new MemoryStream();
        var buffer = new byte[64 * 1024];
        while (memory.Length <= MaxHttpResponseBytes)
        {
            var read = await stream.ReadAsync(buffer, cts.Token);
            if (read == 0) break;
            await memory.WriteAsync(buffer.AsMemory(0, read), cts.Token);
        }
        if (memory.Length > MaxHttpResponseBytes)
            return Error($" HTTP response exceeds {MaxHttpResponseBytes} bytes");

        var bytes = memory.ToArray();
        var text = Encoding.UTF8.GetString(bytes);
        object? parsed = null;
        try { parsed = JsonSerializer.Deserialize<object>(text); } catch { }

        return Success(new
        {
            statusCode = (int)response.StatusCode,
            reason = response.ReasonPhrase,
            contentType = response.Content.Headers.ContentType?.MediaType,
            text,
            json = parsed
        });
    }

    internal static bool ShouldAutoAuthorizeLocalMcp(
        Uri uri,
        bool mcpMode,
        bool hasExplicitAuthorization,
        int localMcpPort)
    {
        return mcpMode
            && !hasExplicitAuthorization
            && uri.IsLoopback
            && uri.Port == localMcpPort;
    }

    private static int ResolveLocalMcpPort()
    {
        return int.TryParse(Environment.GetEnvironmentVariable("OPENCLAW_MCP_PORT"), out var configuredPort)
            && configuredPort is > 0 and <= 65535
                ? configuredPort
                : 8765;
    }

    private NodeInvokeResponse WindowList(JsonElement args)
    {
        EnsureWindows();
        var pid = GetIntArg(args, "pid", 0);
        var visibleOnly = GetBoolArg(args, "visibleOnly", true);
        var windows = EnumerateWindows()
            .Where(w => (pid <= 0 || w.ProcessId == pid) && (!visibleOnly || w.Visible))
            .ToArray();
        return Success(new { windows });
    }

    private NodeInvokeResponse WindowInspect(JsonElement args)
    {
        EnsureWindows();
        var pid = GetIntArg(args, "pid", 0);
        var hwnd = ParseHwnd(GetStringArg(args, "hwnd"));
        var window = ResolveExactWindow(pid, hwnd);
        return Success(window);
    }

    private NodeInvokeResponse WindowInput(JsonElement args)
    {
        EnsureWindows();
        var pid = GetIntArg(args, "pid", 0);
        var hwnd = ParseHwnd(GetStringArg(args, "hwnd"));
        if (pid <= 0 || hwnd == IntPtr.Zero)
            return Error("window.input requires both exact pid and hwnd");

        var target = ResolveExactWindow(pid, hwnd);
        var kind = (GetStringArg(args, "kind") ?? "").Trim().ToLowerInvariant();
        var posted = true;
        var postedCount = 0;

        bool Post(uint message, IntPtr wParam, IntPtr lParam)
        {
            var ok = Native.PostMessage(hwnd, message, wParam, lParam);
            if (ok) postedCount++;
            posted &= ok;
            return ok;
        }

        bool PostKey(int vk, bool keyUp)
        {
            var system = GetBoolArg(args, "system", false) || vk == Native.VK_MENU;
            var message = keyUp
                ? (system ? Native.WM_SYSKEYUP : Native.WM_KEYUP)
                : (system ? Native.WM_SYSKEYDOWN : Native.WM_KEYDOWN);
            return Post(message, (IntPtr)vk, MakeKeyLParam(vk, keyUp, system));
        }

        switch (kind)
        {
            case "key":
            case "keypress":
            {
                var vk = ResolveVirtualKey(args);
                PostKey(vk, keyUp: false);
                PostKey(vk, keyUp: true);
                break;
            }
            case "keydown":
                PostKey(ResolveVirtualKey(args), keyUp: false);
                break;
            case "keyup":
                PostKey(ResolveVirtualKey(args), keyUp: true);
                break;
            case "text":
            {
                var value = GetStringArg(args, "text") ?? "";
                foreach (var ch in value)
                    Post(Native.WM_CHAR, (IntPtr)ch, (IntPtr)1);
                break;
            }
            case "mousemove":
            {
                var (x, y) = RequireClientPoint(args, target);
                Post(Native.WM_MOUSEMOVE, IntPtr.Zero, MakeMouseLParam(x, y));
                break;
            }
            case "click":
            case "leftclick":
            {
                var (x, y) = RequireClientPoint(args, target);
                var lp = MakeMouseLParam(x, y);
                Post(Native.WM_MOUSEMOVE, IntPtr.Zero, lp);
                Post(Native.WM_LBUTTONDOWN, (IntPtr)Native.MK_LBUTTON, lp);
                Post(Native.WM_LBUTTONUP, IntPtr.Zero, lp);
                break;
            }
            case "leftdown":
            case "leftup":
            case "rightdown":
            case "rightup":
            case "middledown":
            case "middleup":
            {
                var (x, y) = RequireClientPoint(args, target);
                var lp = MakeMouseLParam(x, y);
                var (message, keyState) = kind switch
                {
                    "leftdown" => (Native.WM_LBUTTONDOWN, Native.MK_LBUTTON),
                    "leftup" => (Native.WM_LBUTTONUP, 0),
                    "rightdown" => (Native.WM_RBUTTONDOWN, Native.MK_RBUTTON),
                    "rightup" => (Native.WM_RBUTTONUP, 0),
                    "middledown" => (Native.WM_MBUTTONDOWN, Native.MK_MBUTTON),
                    _ => (Native.WM_MBUTTONUP, 0)
                };
                Post(message, (IntPtr)keyState, lp);
                break;
            }
            case "rightclick":
            case "middleclick":
            {
                var (x, y) = RequireClientPoint(args, target);
                var lp = MakeMouseLParam(x, y);
                Post(Native.WM_MOUSEMOVE, IntPtr.Zero, lp);
                if (kind == "rightclick")
                {
                    Post(Native.WM_RBUTTONDOWN, (IntPtr)Native.MK_RBUTTON, lp);
                    Post(Native.WM_RBUTTONUP, IntPtr.Zero, lp);
                }
                else
                {
                    Post(Native.WM_MBUTTONDOWN, (IntPtr)Native.MK_MBUTTON, lp);
                    Post(Native.WM_MBUTTONUP, IntPtr.Zero, lp);
                }
                break;
            }
            case "wheel":
            {
                var (x, y) = RequireClientPoint(args, target);
                var point = new Native.Point { X = x, Y = y };
                if (!Native.ClientToScreen(hwnd, ref point))
                    throw new InvalidOperationException("ClientToScreen failed for target window");
                var delta = Math.Clamp(GetIntArg(args, "delta", Native.WHEEL_DELTA), -1200, 1200);
                if (delta == 0)
                    throw new InvalidOperationException("wheel delta must be non-zero");
                var wheelWParam = (IntPtr)(delta << 16);
                Post(Native.WM_MOUSEWHEEL, wheelWParam, MakeMouseLParam(point.X, point.Y));
                break;
            }
            default:
                return Error("kind must be key, keydown, keyup, text, mousemove, click, leftdown, leftup, rightclick, rightdown, rightup, middleclick, middledown, middleup, or wheel");
        }

        var targetAfter = ResolveExactWindow(pid, hwnd);
        return Success(new
        {
            posted,
            postedCount,
            kind,
            target = targetAfter,
            scope = "exact-pid-hwnd",
            globalInputUsed = false,
            foregroundChanged = false,
            cursorMoved = false
        });
    }

    private async Task<NodeInvokeResponse> WindowCaptureAsync(JsonElement args, CancellationToken cancellationToken)
    {
        EnsureWindows();
        var pid = GetIntArg(args, "pid", 0);
        var hwnd = ParseHwnd(GetStringArg(args, "hwnd"));
        if (pid <= 0 || hwnd == IntPtr.Zero)
            return Error("window.capture requires both exact pid and hwnd");
        if (WindowCaptureRequested == null)
            return Error("Exact-window capture backend is not available");

        var target = ResolveExactWindow(pid, hwnd);
        if (target.ClientWidth <= 0 || target.ClientHeight <= 0)
            return Error("Target window has an empty client area");
        if (Native.IsIconic(hwnd))
            return Error("Target window is minimized; exact-window capture refuses to restore or focus it");
        var pixels = (long)target.ClientWidth * target.ClientHeight;
        if (pixels > MaxWindowCapturePixels)
            return Error($"Target client area exceeds the {MaxWindowCapturePixels:N0}-pixel safety cap");

        var timeoutMs = Math.Clamp(GetIntArg(args, "timeoutMs", 3000), 500, 5000);
        var outputPath = GetStringArg(args, "path");
        var createParents = GetBoolArg(args, "createParents", false);
        if (string.IsNullOrWhiteSpace(outputPath))
        {
            var pictures = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);
            var directory = Path.Combine(pictures, "OpenClaw Captures");
            Directory.CreateDirectory(directory);
            var safeName = SanitizeFileName(target.ProcessName ?? "window");
            var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss-fff");
            outputPath = Path.Combine(directory, $"{safeName}_{pid}_{target.Hwnd}_{stamp}.png");
        }
        else
        {
            outputPath = Path.GetFullPath(outputPath);
            if (!string.Equals(Path.GetExtension(outputPath), ".png", StringComparison.OrdinalIgnoreCase))
                return Error("window.capture currently saves PNG only");
            var parent = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrEmpty(parent) && !Directory.Exists(parent))
            {
                if (!createParents)
                    return Error($"Parent directory does not exist: {parent}");
                Directory.CreateDirectory(parent);
            }
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeoutMs);
        WindowCaptureResult capture;
        try
        {
            capture = await WindowCaptureRequested(
                new WindowCaptureArgs
                {
                    ProcessId = pid,
                    Hwnd = hwnd.ToInt64(),
                    MaxPixels = MaxWindowCapturePixels,
                    MaxOutputBytes = MaxWindowCaptureBytes
                },
                cts.Token);
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            return Error($"Exact-window capture exceeded the {timeoutMs} ms safety timeout");
        }

        if (capture.PngBytes.Length == 0)
            return Error("Capture backend returned an empty PNG");
        if (capture.PngBytes.Length > MaxWindowCaptureBytes)
            return Error($"Capture output exceeds the {MaxWindowCaptureBytes} byte safety cap");
        if (capture.Width <= 0 || capture.Height <= 0 || (long)capture.Width * capture.Height > MaxWindowCapturePixels)
            return Error("Capture backend returned dimensions outside the safety bounds");

        var targetAfter = ResolveExactWindow(pid, hwnd);
        var full = Path.GetFullPath(outputPath);
        var temp = full + ".awl-partial-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllBytesAsync(temp, capture.PngBytes, cts.Token);
            File.Move(temp, full, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
        }

        var hash = Convert.ToHexString(SHA256.HashData(capture.PngBytes)).ToLowerInvariant();
        return Success(new
        {
            path = full,
            format = "png",
            capture.Width,
            capture.Height,
            bytes = capture.PngBytes.Length,
            sha256 = hash,
            target = targetAfter,
            backend = "Windows.Graphics.Capture",
            scope = "exact-pid-hwnd",
            captureRunsOutsideTargetProcess = true,
            captureHookInjectedIntoTarget = false,
            foregroundChanged = false,
            globalInputUsed = false,
            timeoutMs
        });
    }

    private static object ProcessView(Process process)
    {
        string? path = null;
        string? title = null;
        DateTime? startTime = null;
        bool hasExited;
        try { hasExited = process.HasExited; } catch { hasExited = true; }
        try { path = process.MainModule?.FileName; } catch { }
        try { title = process.MainWindowTitle; } catch { }
        try { startTime = process.StartTime.ToUniversalTime(); } catch { }
        return new { pid = process.Id, name = process.ProcessName, path, title, startTimeUtc = startTime, hasExited };
    }

    private async Task<NodeInvokeResponse> RunProcessAsync(
        string fileName,
        IEnumerable<string> arguments,
        string? cwd,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = string.IsNullOrWhiteSpace(cwd) ? Environment.CurrentDirectory : cwd,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var arg in arguments) psi.ArgumentList.Add(arg);
        using var process = Process.Start(psi) ?? throw new InvalidOperationException($"Unable to start {fileName}");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeoutMs);
        var stdoutTask = process.StandardOutput.ReadToEndAsync(cts.Token);
        var stderrTask = process.StandardError.ReadToEndAsync(cts.Token);
        await process.WaitForExitAsync(cts.Token);
        return Success(new
        {
            processId = process.Id,
            exitCode = process.ExitCode,
            stdout = await stdoutTask,
            stderr = await stderrTask
        });
    }

    private async Task<NodeInvokeResponse> RunJsonProcessAsync(
        string fileName,
        IEnumerable<string> arguments,
        string? cwd,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        var response = await RunProcessAsync(fileName, arguments, cwd, timeoutMs, cancellationToken);
        if (!response.Ok || response.Payload == null) return response;
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(response.Payload));
        var root = doc.RootElement;
        var stdout = root.GetProperty("stdout").GetString() ?? "";
        var stderr = root.GetProperty("stderr").GetString() ?? "";
        var exitCode = root.GetProperty("exitCode").GetInt32();
        if (exitCode != 0)
        {
            var detail = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
            return Error(string.IsNullOrWhiteSpace(detail)
                ? $"structured helper process exited with code {exitCode}"
                : detail.Trim());
        }

        object? json;
        try
        {
            json = JsonSerializer.Deserialize<object>(stdout);
        }
        catch (JsonException ex)
        {
            return Error($"structured helper returned invalid JSON: {ex.Message}");
        }
        return Success(new
        {
            processId = root.GetProperty("processId").GetInt32(),
            exitCode,
            result = json
        });
    }

    private static string RequirePath(JsonElement args, string name)
    {
        if (args.ValueKind != JsonValueKind.Object ||
            !args.TryGetProperty(name, out var value) ||
            value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()))
            throw new InvalidOperationException($" {name} is required");
        return Path.GetFullPath(value.GetString()!);
    }

    private static bool IsPrivateOrLoopback(Uri uri)
    {
        if (uri.IsLoopback) return true;
        if (!IPAddress.TryParse(uri.Host, out var ip))
            return false;
        if (IPAddress.IsLoopback(ip)) return true;
        var bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
            return bytes[0] == 10 ||
                   (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168) ||
                   (bytes[0] == 169 && bytes[1] == 254);
        return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal;
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("window operations are Windows-only");
    }

    private static IntPtr ParseHwnd(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return IntPtr.Zero;
        var text = raw.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return long.TryParse(text[2..], System.Globalization.NumberStyles.HexNumber, null, out var hex)
                ? (IntPtr)hex
                : IntPtr.Zero;
        return long.TryParse(text, out var value) ? (IntPtr)value : IntPtr.Zero;
    }

    private static WindowView ResolveExactWindow(int pid, IntPtr hwnd)
    {
        if (pid <= 0  || hwnd == IntPtr.Zero)
            throw new InvalidOperationException("Exact pid and hwnd are required");
        if (!Native.IsWindow(hwnd))
            throw new InvalidOperationException("HWND is not a live window");
        Native.GetWindowThreadProcessId(hwnd, out var actualPid);
        if (actualPid != (uint)pid)
            throw new InvalidOperationException(" HWND belongs to PID {actualPid}, not requested PID {pid}");
        return ReadWindow(hwnd);
    }

    private static WindowView[] EnumerateWindows()
    {
        var list = new List<WindowView>();
        Native.EnumWindows((hwnd, _) =>
        {
            try { list.Add(ReadWindow(hwnd)); } catch { }
            return true;
        }, IntPtr.Zero);
        return list.ToArray();
    }

    private static WindowView ReadWindow(IntPtr hwnd)
    {
        Native.GetWindowThreadProcessId(hwnd, out var pid);
        var title = new StringBuilder(2048);
        Native.GetWindowText(hwnd, title, title.Capacity);
        var className = new StringBuilder(512);
        Native.GetClassName(hwnd, className, className.Capacity);
        Native.GetClientRect(hwnd, out var rect);
        string? processName = null;
        try { using var p = Process.GetProcessById((int)pid); processName = p.ProcessName; } catch { }
        return new WindowView(
            $"0x{hwnd.ToInt64():X}",
            (int)pid,
            processName,
            title.ToString(),
            className.ToString(),
            Native.IsWindowVisible(hwnd),
            Math.Max(0, rect.Right - rect.Left),
            Math.Max(0, rect.Bottom - rect.Top));
    }

    private static int ResolveVirtualKey(JsonElement args)
    {
        var vk = args.TryGetProperty("vk", out var vkElement) && vkElement.ValueKind == JsonValueKind.Number
            ? vkElement.GetInt32()
            : 0;
        if (vk is >= 1 and <= 255) return vk;

        var key = args.TryGetProperty("key", out var keyElement) && keyElement.ValueKind == JsonValueKind.String
            ? keyElement.GetString()?.Trim().ToUpperInvariant()
            : null;
        if (string.IsNullOrWhiteSpace(key))
            throw new InvalidOperationException("key or vk is required");
        if (key.Length == 1)
        {
            var c = key[0];
            if (c is >= 'A' and <= 'Z' || c is >= '0' and <= '9') return c;
        }
        return key switch
        {
            "SPACE" => 0x20,
            "ENTER" or "RETURN" => 0x0D,
            "ESC" or "ESCAPE" => 0x1B,
            "TAB" => 0x09,
            "BACKSPACE" => 0x08,
            "LEFT" => 0x25,
            "UP" => 0x26,
            "RIGHT" => 0x27,
            "DOWN" => 0x28,
            "HOME" => 0x24,
            "END" => 0x23,
            "PGUP" or "PAGEUP" => 0x21,
            "PGDN" or "PAGEDOWN" => 0x22,
            "DELETE" => 0x2E,
            "INSERT" => 0x2D,
            "SHIFT" => 0x10,
            "CTRL" or "CONTROL" => 0x11,
            "ALT" => 0x12,
            _ when key.StartsWith("F") && int.TryParse(key[1..], out var f) && f is >= 1 and <= 24 => 0x70 + f - 1,
            _ => throw new InvalidOperationException($" Unsupported key name: {key}; pass vk for other virtual keys")
        };
    }

    private static (int X, int Y) RequireClientPoint(JsonElement args, WindowView target)
    {
        if (!args.TryGetProperty("x", out var xElement) || xElement.ValueKind != JsonValueKind.Number ||
            !args.TryGetProperty("y", out var yElement) || yElement.ValueKind != JsonValueKind.Number)
            throw new InvalidOperationException("x and y client coordinates are required");
        var x = xElement.GetInt32();
        var y = yElement.GetInt32();
        if (x < 0 || y < 0 || x >= target.ClientWidth || y >= target.ClientHeight)
            throw new InvalidOperationException($" Point {x},{y} is outside client area {target.ClientWidth}x{target.ClientHeight}");
        return (x, y);
    }

    private static IntPtr MakeKeyLParam(int vk, bool keyUp, bool system)
    {
        var scan = Native.MapVirtualKey((uint)vk, Native.MAPVK_VK_TO_VSC_EX);
        var scanCode = scan & 0xFF;
        var prefix = (scan >> 8) & 0xFF;
        uint value = 1 | (scanCode << 16);
        if (prefix is 0xE0 or 0xE1) value |= 1u << 24;
        if (system) value |= 1u << 29;
        if (keyUp) value |= (1u << 30) | (1u << 31);
        return (IntPtr)unchecked((int)value);
    }

    private static IntPtr MakeMouseLParam(int x, int y)
        => (IntPtr)unchecked((int)(((uint)(ushort)y << 16) | (ushort)x));

    private static string SanitizeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var chars = value.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray();
        var result = new string(chars).Trim();
        return string.IsNullOrWhiteSpace(result) ? "window" : result;
    }

    private sealed record WindowView(
        string Hwnd,
        int ProcessId,
        string? ProcessName,
        string Title,
        string ClassName,
        bool Visible,
        int ClientWidth,
        int ClientHeight);

    private static class Native
    {
        internal const uint WM_KEYDOWN = 0x0100;
        internal const uint WM_KEYUP = 0x0101;
        internal const uint WM_CHAR = 0x0102;
        internal const uint WM_SYSKEYDOWN = 0x0104;
        internal const uint WM_SYSKEYUP = 0x0105;
        internal const uint WM_MOUSEMOVE = 0x0200;
        internal const uint WM_LBUTTONDOWN = 0x0201;
        internal const uint WM_LBUTTONUP = 0x0202;
        internal const uint WM_RBUTTONDOWN = 0x0204;
        internal const uint WM_RBUTTONUP = 0x0205;
        internal const uint WM_MBUTTONDOWN = 0x0207;
        internal const uint WM_MBUTTONUP = 0x0208;
        internal const uint WM_MOUSEWHEEL = 0x020A;
        internal const int MK_LBUTTON = 0x0001;
        internal const int MK_RBUTTON = 0x0002;
        internal const int MK_MBUTTON = 0x0010;
        internal const int WHEEL_DELTA = 120;
        internal const int VK_MENU = 0x12;
        internal const uint MAPVK_VK_TO_VSC_EX = 4;

        internal delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsWindow(IntPtr hwnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsWindowVisible(IntPtr hwnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsIconic(IntPtr hwnd);

        [DllImport("user32.dll", SetLastError = true)]
        internal static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        internal static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int maxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        internal static extern int GetClassName(IntPtr hwnd, StringBuilder className, int maxCount);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetClientRect(IntPtr hwnd, out Rect rect);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool PostMessage(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        internal static extern uint MapVirtualKey(uint code, uint mapType);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ClientToScreen(IntPtr hwnd, ref Point point);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint GetFinalPathNameByHandle(
            IntPtr file,
            StringBuilder path,
            uint pathCapacity,
            uint flags);

        [StructLayout(LayoutKind.Sequential)]
        internal struct Point
        {
            public int X;
            public int Y;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct Rect
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }
    }
}


public sealed class WindowCaptureArgs
{
    public int ProcessId { get; set; }
    public long Hwnd { get; set; }
    public int MaxPixels { get; set; }
    public int MaxOutputBytes { get; set; }
}

public sealed class WindowCaptureResult
{
    public int Width { get; set; }
    public int Height { get; set; }
    public byte[] PngBytes { get; set; } = Array.Empty<byte>();
}
