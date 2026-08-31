using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Graphics.Capture;
using Windows.Graphics.DirectX;
using Windows.Graphics.DirectX.Direct3D11;
using Windows.Graphics.Imaging;
using Windows.Media.Core;
using Windows.Media.MediaProperties;
using Windows.Media.Transcoding;
using Windows.Storage.Streams;
using OpenClaw.Shared;
using OpenClaw.Shared.Capabilities;
using WinRT;

namespace OpenClawTray.Services;

/// <summary>
/// Records the screen using Windows.Graphics.Capture and encodes to MP4 via MediaTranscoder.
/// </summary>
internal sealed class ScreenRecordingService : IDisposable
{
    private readonly IOpenClawLogger _logger;

    private const int MaxFps        = 60;
    private const int MinFps        = 1;
    private const int MinDurationMs = 250;
    private const int MaxDurationMs = 60_000;
    private const int PoolBuffers   = 2;

    // BGRA frame buffer safety cap: 128 MB across all queued frames.
    // At 1080p (8 MB/frame) this allows ~16 frames; at 720p (~4 MB) ~32 frames.
    // Frames beyond this limit are dropped to prevent OOM on long/high-fps recordings.
    private const long MaxFrameBufferBytes = 128L * 1024 * 1024;
    private const int MaxExactWindowCapturePixels = 12_000_000;
    private const int MaxExactWindowCaptureBytes = 64 * 1024 * 1024;

    public ScreenRecordingService(IOpenClawLogger logger)
    {
        _logger = logger;
    }

    // Public API

    public async Task<ScreenRecordResult> RecordAsync(
        ScreenRecordArgs args,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var durationMs  = Math.Clamp(args.DurationMs, MinDurationMs, MaxDurationMs);
        var fps         = Math.Clamp((int)Math.Round(args.Fps), MinFps, MaxFps);
        var screenIndex = args.ScreenIndex;

        _logger.Info($"[ScreenRecording] duration={durationMs}ms fps={fps} screen={screenIndex}");

        var item    = CreateCaptureItem(screenIndex);
        var width   = item.Size.Width;
        var height  = item.Size.Height;
        var d3d     = CreateDirect3DDevice();

        Direct3D11CaptureFramePool? pool    = null;
        GraphicsCaptureSession?     session = null;
        var latestFrame = (Direct3D11CaptureFrame?)null;
        using var ready = new SemaphoreSlim(0, 1);
        var frames = new List<byte[]>();
        var frameBytes = (long)width * height * 4; // BGRA bytes per frame

        try
        {
            pool = Direct3D11CaptureFramePool.CreateFreeThreaded(
                d3d,
                DirectXPixelFormat.B8G8R8A8UIntNormalized,
                PoolBuffers,
                new global::Windows.Graphics.SizeInt32 { Width = width, Height = height });

            session = pool.CreateCaptureSession(item);
            session.IsCursorCaptureEnabled = false;

            pool.FrameArrived += (p, _) =>
            {
                var f = p.TryGetNextFrame();
                if (f == null) return;
                Interlocked.Exchange(ref latestFrame, f)?.Dispose();
                // slopwatch-ignore: SW003 Cleanup is best-effort; failure cannot improve caller state and the original outcome is preserved.
                try { ready.Release(); } catch { /* already signaled */ }
            };

            session.StartCapture();

            var intervalMs  = 1000 / fps;
            var deadline    = DateTime.UtcNow.AddMilliseconds(durationMs);
            var nextCapture = DateTime.UtcNow;

            while (DateTime.UtcNow < deadline)
            {
                var waitMs = (int)(nextCapture - DateTime.UtcNow).TotalMilliseconds;
                if (waitMs > 0)
                    await Task.Delay(waitMs, cancellationToken);

                if (!await ready.WaitAsync(intervalMs * 2, cancellationToken))
                    continue;

                var frame = Interlocked.Exchange(ref latestFrame, null);
                if (frame == null) continue;

                using (frame)
                {
                    if (frames.Count * frameBytes >= MaxFrameBufferBytes)
                    {
                        _logger.Warn($"[ScreenRecording] Frame buffer cap reached ({MaxFrameBufferBytes / 1024 / 1024} MB), stopping early.");
                        break;
                    }

                    try
                    {
                        using var bmp = await SoftwareBitmap
                            .CreateCopyFromSurfaceAsync(frame.Surface)
                            .AsTask(cancellationToken);
                        frames.Add(ExtractBitmapBytes(bmp));
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        _logger.Warn($"[ScreenRecording] Frame skipped: {ex.Message}");
                    }
                }

                nextCapture = nextCapture.AddMilliseconds(intervalMs);
            }
        }
        finally
        {
            session?.Dispose();
            pool?.Dispose();
            (d3d as IDisposable)?.Dispose();
            Interlocked.Exchange(ref latestFrame, null)?.Dispose();
        }

        _logger.Info($"[ScreenRecording] Captured {frames.Count} frames, encoding...");

        cancellationToken.ThrowIfCancellationRequested();
        var base64 = await EncodeToMp4Async(frames, width, height, fps, cancellationToken);
        var actualDurationMs = (int)Math.Round(frames.Count * 1000.0 / fps);

        return new ScreenRecordResult
        {
            Format      = "mp4",
            Base64      = base64,
            DurationMs  = actualDurationMs,
            Fps         = fps,
            ScreenIndex = screenIndex,
            Width       = width,
            Height      = height,
            HasAudio    = false,
        };
    }

    public async Task<WindowCaptureResult> CaptureWindowAsync(
        WindowCaptureArgs args,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!GraphicsCaptureSession.IsSupported())
            throw new InvalidOperationException("Windows Graphics Capture is not supported on this system");
        if (args.ProcessId <= 0 || args.Hwnd == 0)
            throw new InvalidOperationException("Exact process id and HWND are required");

        var item = CreateCaptureItemForWindow((IntPtr)args.Hwnd);
        var width = item.Size.Width;
        var height = item.Size.Height;
        if (width <= 0 || height <= 0)
            throw new InvalidOperationException("Target capture item has an empty surface");
        var maxPixels = Math.Min(
            args.MaxPixels > 0 ? args.MaxPixels : MaxExactWindowCapturePixels,
            MaxExactWindowCapturePixels);
        if ((long)width * height > maxPixels)
            throw new InvalidOperationException($"Target capture surface exceeds the {maxPixels:N0}-pixel safety cap");

        var d3d = CreateDirect3DDevice();
        Direct3D11CaptureFramePool? pool = null;
        GraphicsCaptureSession? session = null;
        Direct3D11CaptureFrame? capturedFrame = null;
        using var ready = new SemaphoreSlim(0, 1);
        TypedEventHandler<Direct3D11CaptureFramePool, object>? handler = null;

        try
        {
            pool = Direct3D11CaptureFramePool.CreateFreeThreaded(
                d3d,
                DirectXPixelFormat.B8G8R8A8UIntNormalized,
                1,
                new global::Windows.Graphics.SizeInt32 { Width = width, Height = height });
            session = pool.CreateCaptureSession(item);
            session.IsCursorCaptureEnabled = false;

            handler = (sender, _) =>
            {
                var frame = sender.TryGetNextFrame();
                if (frame == null) return;
                if (Interlocked.CompareExchange(ref capturedFrame, frame, null) != null)
                {
                    frame.Dispose();
                    return;
                }
                try { ready.Release(); } catch (SemaphoreFullException) { }
            };
            pool.FrameArrived += handler;
            session.StartCapture();

            await ready.WaitAsync(cancellationToken);
            var frame = Interlocked.Exchange(ref capturedFrame, null)
                ?? throw new InvalidOperationException("Capture signaled without a frame");
            using (frame)
            using (var bitmap = await SoftwareBitmap.CreateCopyFromSurfaceAsync(frame.Surface).AsTask(cancellationToken))
            {
                var png = await EncodePngAsync(bitmap, cancellationToken);
                var maxBytes = Math.Min(
                    args.MaxOutputBytes > 0 ? args.MaxOutputBytes : MaxExactWindowCaptureBytes,
                    MaxExactWindowCaptureBytes);
                if (png.Length > maxBytes)
                    throw new InvalidOperationException($"PNG output exceeds the {maxBytes} byte safety cap");

                return new WindowCaptureResult
                {
                    Width = bitmap.PixelWidth,
                    Height = bitmap.PixelHeight,
                    PngBytes = png
                };
            }
        }
        finally
        {
            if (pool != null && handler != null)
                pool.FrameArrived -= handler;
            Interlocked.Exchange(ref capturedFrame, null)?.Dispose();
            session?.Dispose();
            pool?.Dispose();
            (d3d as IDisposable)?.Dispose();
        }
    }

    public void Dispose()
    {
    }

    private static async Task<byte[]> EncodePngAsync(
        SoftwareBitmap bitmap,
        CancellationToken cancellationToken)
    {
        using var output = new InMemoryRandomAccessStream();
        var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, output).AsTask(cancellationToken);
        encoder.SetSoftwareBitmap(bitmap);
        await encoder.FlushAsync().AsTask(cancellationToken);
        if (output.Size > MaxExactWindowCaptureBytes)
            throw new InvalidOperationException($"PNG output exceeds the {MaxExactWindowCaptureBytes} byte safety cap");
        if (output.Size > uint.MaxValue)
            throw new InvalidOperationException("PNG output is too large to read safely");

        var size = (uint)output.Size;
        output.Seek(0);
        using var reader = new DataReader(output.GetInputStreamAt(0));
        await reader.LoadAsync(size).AsTask(cancellationToken);
        var bytes = new byte[size];
        reader.ReadBytes(bytes);
        return bytes;
    }

    // Encoding

    private static async Task<string> EncodeToMp4Async(
        List<byte[]> frames,
        int width,
        int height,
        int fps,
        CancellationToken cancellationToken)
    {
        if (frames.Count == 0)
            throw new InvalidOperationException("No frames to encode");

        var encWidth  = (uint)(width  & ~1);
        var encHeight = (uint)(height & ~1);
        var fi = new[] { 0 };

        MediaStreamSource MakeMss()
        {
            fi[0] = 0;
            var inputProps = VideoEncodingProperties.CreateUncompressed(
                MediaEncodingSubtypes.Nv12, encWidth, encHeight);
            inputProps.FrameRate.Numerator   = (uint)fps;
            inputProps.FrameRate.Denominator = 1;
            var mss = new MediaStreamSource(new VideoStreamDescriptor(inputProps));
            mss.BufferTime = TimeSpan.Zero;
            mss.SampleRequested += (_, e) =>
            {
                if (fi[0] >= frames.Count) { e.Request.Sample = null; return; }
                var nv12 = BgraToNv12(frames[fi[0]], width, height, (int)encWidth, (int)encHeight);
                var ts   = TimeSpan.FromTicks((long)(fi[0] * 10_000_000.0 / fps));
                var dur  = TimeSpan.FromTicks((long)(10_000_000.0 / fps));
                using var dw = new DataWriter();
                dw.WriteBytes(nv12);
                var sample = MediaStreamSample.CreateFromBuffer(dw.DetachBuffer(), ts);
                sample.Duration = dur;
                e.Request.Sample = sample;
                fi[0]++;
            };
            return mss;
        }

        MediaEncodingProfile MakeProfile()
        {
            var profile = MediaEncodingProfile.CreateMp4(VideoEncodingQuality.Auto);
            profile.Video.Width                 = encWidth;
            profile.Video.Height                = encHeight;
            profile.Video.Bitrate               = 4_000_000;
            profile.Video.FrameRate.Numerator   = (uint)fps;
            profile.Video.FrameRate.Denominator = 1;
            profile.Audio = null;
            return profile;
        }

        foreach (var hwEnabled in new[] { true, false })
        {
            using var output = new InMemoryRandomAccessStream();
            var transcoder = new MediaTranscoder { HardwareAccelerationEnabled = hwEnabled };
            PrepareTranscodeResult result;
            try
            {
                result = await transcoder
                    .PrepareMediaStreamSourceTranscodeAsync(MakeMss(), output, MakeProfile())
                    .AsTask(cancellationToken);
            }
            catch (System.Runtime.InteropServices.COMException) when (hwEnabled)
            {
                continue;
            }
            if (!result.CanTranscode) continue;
            await result.TranscodeAsync().AsTask(cancellationToken);
            var size = (uint)output.Size;
            if (size == 0) continue;
            var dr = new DataReader(output.GetInputStreamAt(0));
            await dr.LoadAsync(size).AsTask(cancellationToken);
            var bytes = new byte[size];
            dr.ReadBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        throw new InvalidOperationException("No encoder available (hardware or software)");
    }

    private static byte[] BgraToNv12(byte[] bgra, int srcWidth, int srcHeight,
        int encWidth, int encHeight)
    {
        var nv12 = new byte[encWidth * encHeight * 3 / 2];
        for (int y = 0; y < encHeight; y++)
        for (int x = 0; x < encWidth; x++)
        {
            int i = (y * srcWidth + x) * 4;
            int b = bgra[i], g = bgra[i + 1], r = bgra[i + 2];
            nv12[y * encWidth + x] = (byte)(((66 * r + 129 * g + 25 * b + 128) >> 8) + 16);
        }
        int uvBase = encWidth * encHeight;
        for (int y = 0; y < encHeight; y += 2)
        for (int x = 0; x < encWidth; x += 2)
        {
            int i    = (y * srcWidth + x) * 4;
            int b    = bgra[i], g = bgra[i + 1], r = bgra[i + 2];
            int uvIdx = uvBase + (y / 2) * encWidth + x;
            nv12[uvIdx]     = (byte)(((-38 * r -  74 * g + 112 * b + 128) >> 8) + 128);
            nv12[uvIdx + 1] = (byte)(((112 * r -  94 * g -  18 * b + 128) >> 8) + 128);
        }
        return nv12;
    }

    // D3D11 / WinRT interop

    // IID_IDXGIDevice
    private static readonly Guid IID_DXGIDevice =
        new Guid("54ec77fa-1377-44e6-8c32-88fd5f44c84c");

    private static IDirect3DDevice CreateDirect3DDevice()
    {
        // D3D_DRIVER_TYPE_HARDWARE=1, D3D11_CREATE_DEVICE_BGRA_SUPPORT=0x20, D3D11_SDK_VERSION=7
        var hr = D3D11CreateDevice(IntPtr.Zero, 1, IntPtr.Zero, 0x20, IntPtr.Zero, 0, 7,
            out var d3dPtr, IntPtr.Zero, IntPtr.Zero);
        Marshal.ThrowExceptionForHR(hr);
        if (d3dPtr == IntPtr.Zero)
            throw new InvalidOperationException("D3D11 device creation returned a null device.");

        var iid = IID_DXGIDevice;
        hr = Marshal.QueryInterface(d3dPtr, in iid, out var dxgiPtr);
        Marshal.Release(d3dPtr);
        Marshal.ThrowExceptionForHR(hr);
        if (dxgiPtr == IntPtr.Zero)
            throw new InvalidOperationException("D3D11 device did not expose IDXGIDevice.");

        hr = NativeCreateDirect3D11DeviceFromDXGIDevice(dxgiPtr, out var winrtPtr);
        Marshal.Release(dxgiPtr);
        Marshal.ThrowExceptionForHR(hr);
        if (winrtPtr == IntPtr.Zero)
            throw new InvalidOperationException("WinRT Direct3D device creation returned a null device.");

        var device = MarshalInterface<IDirect3DDevice>.FromAbi(winrtPtr);
        Marshal.Release(winrtPtr);
        return device;
    }

    private static GraphicsCaptureItem CreateCaptureItemForWindow(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero)
            throw new ArgumentException("HWND must be non-zero", nameof(hwnd));

        const string classId = "Windows.Graphics.Capture.GraphicsCaptureItem";
        var iid = typeof(IGraphicsCaptureItemInterop).GUID;
        var hr = WindowsCreateString(classId, classId.Length, out var hstring);
        Marshal.ThrowExceptionForHR(hr);
        if (hstring == IntPtr.Zero)
            throw new InvalidOperationException("GraphicsCaptureItem activation string was null.");

        try
        {
            hr = RoGetActivationFactory(hstring, ref iid, out var factoryPtr);
            Marshal.ThrowExceptionForHR(hr);
            if (factoryPtr == IntPtr.Zero)
                throw new InvalidOperationException("GraphicsCaptureItem activation factory was null.");

            var factory = (IGraphicsCaptureItemInterop)Marshal.GetObjectForIUnknown(factoryPtr);
            Marshal.Release(factoryPtr);
            var itemIid = new Guid("AF86E2E0-B12D-4C6A-9C5A-D7AA65101E90");
            factory.CreateForWindow(hwnd, in itemIid, out var itemPtr);
            if (itemPtr == IntPtr.Zero)
                throw new InvalidOperationException("GraphicsCaptureItem creation returned a null item.");

            var item = MarshalInspectable<GraphicsCaptureItem>.FromAbi(itemPtr);
            Marshal.Release(itemPtr);
            return item;
        }
        finally
        {
            WindowsDeleteString(hstring);
        }
    }

    private static GraphicsCaptureItem CreateCaptureItem(int screenIndex)
    {
        var monitors = GetMonitorHandles();
        if (monitors.Count == 0)
            throw new InvalidOperationException("No screens available for capture");
        if (screenIndex < 0 || screenIndex >= monitors.Count)
            throw new ArgumentOutOfRangeException(nameof(screenIndex),
                $"Screen index {screenIndex} is out of range (0-{monitors.Count - 1})");

        const string classId = "Windows.Graphics.Capture.GraphicsCaptureItem";
        var iid = typeof(IGraphicsCaptureItemInterop).GUID;

        var hr = WindowsCreateString(classId, classId.Length, out var hstring);
        Marshal.ThrowExceptionForHR(hr);
        if (hstring == IntPtr.Zero)
            throw new InvalidOperationException("GraphicsCaptureItem activation string was null.");

        try
        {
            hr = RoGetActivationFactory(hstring, ref iid, out var factoryPtr);
            Marshal.ThrowExceptionForHR(hr);
            if (factoryPtr == IntPtr.Zero)
                throw new InvalidOperationException("GraphicsCaptureItem activation factory was null.");

            var factory = (IGraphicsCaptureItemInterop)Marshal.GetObjectForIUnknown(factoryPtr);
            Marshal.Release(factoryPtr);

            var itemIid = new Guid("AF86E2E0-B12D-4C6A-9C5A-D7AA65101E90"); // IInspectable
            factory.CreateForMonitor(monitors[screenIndex], in itemIid, out var itemPtr);
            if (itemPtr == IntPtr.Zero)
                throw new InvalidOperationException("GraphicsCaptureItem creation returned a null item.");

            var item = MarshalInspectable<GraphicsCaptureItem>.FromAbi(itemPtr);
            Marshal.Release(itemPtr);
            return item;
        }
        finally
        {
            WindowsDeleteString(hstring);
        }
    }

    private static List<IntPtr> GetMonitorHandles()
    {
        var handles = new List<IntPtr>();
        EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero,
            (hMon, _, ref _, _) => { handles.Add(hMon); return true; },
            IntPtr.Zero);
        return handles;
    }

    private static byte[] ExtractBitmapBytes(SoftwareBitmap bitmap)
    {
        var capacity = (uint)(bitmap.PixelWidth * bitmap.PixelHeight * 4);
        var buf      = new global::Windows.Storage.Streams.Buffer(capacity);
        bitmap.CopyToBuffer(buf);
        using var dr = DataReader.FromBuffer(buf);
        var bytes = new byte[buf.Length];
        dr.ReadBytes(bytes);
        return bytes;
    }

    // P/Invoke declarations

    [DllImport("d3d11.dll")]
    private static extern int D3D11CreateDevice(
        IntPtr pAdapter, uint DriverType, IntPtr Software, uint Flags,
        IntPtr pFeatureLevels, uint FeatureLevels, uint SDKVersion,
        out IntPtr ppDevice, IntPtr pFeatureLevel, IntPtr ppImmediateContext);

    [DllImport("d3d11.dll", EntryPoint = "CreateDirect3D11DeviceFromDXGIDevice")]
    private static extern int NativeCreateDirect3D11DeviceFromDXGIDevice(
        IntPtr dxgiDevice, out IntPtr graphicsDevice);

    [DllImport("combase.dll")]
    private static extern int WindowsCreateString(
        [MarshalAs(UnmanagedType.LPWStr)] string sourceString, int length, out IntPtr hstring);

    [DllImport("combase.dll")]
    private static extern int WindowsDeleteString(IntPtr hstring);

    [DllImport("combase.dll")]
    private static extern int RoGetActivationFactory(
        IntPtr runtimeClassId, ref Guid iid, out IntPtr factory);

    [DllImport("user32.dll")]
    private static extern bool EnumDisplayMonitors(
        IntPtr hdc, IntPtr lprcClip, MonitorEnumProc lpfnEnum, IntPtr dwData);

    private delegate bool MonitorEnumProc(
        IntPtr hMonitor, IntPtr hdcMonitor, ref RECT lprcMonitor, IntPtr dwData);

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left, Top, Right, Bottom; }

    [ComImport]
    [Guid("3628E81B-3CAC-4C60-B7F4-23CE0E0C3356")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IGraphicsCaptureItemInterop
    {
        void CreateForWindow(IntPtr hwnd, in Guid riid, out IntPtr ppv);
        void CreateForMonitor(IntPtr hMonitor, in Guid riid, out IntPtr ppv);
    }

}
