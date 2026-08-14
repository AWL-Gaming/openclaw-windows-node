using System;
using System.Runtime.InteropServices;

namespace OpenClaw.Connection;

/// <summary>Windows-native process ownership checks used for local endpoint trust decisions.</summary>
public static class WindowsProcessOwnership
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const int TokenUserInformationClass = 1;

    /// <summary>
    /// Returns true only when <paramref name="processId"/> can be proven to run under
    /// the same Windows user SID as the current process. Any lookup failure is denied.
    /// </summary>
    public static bool IsOwnedByCurrentUser(int processId)
    {
        if (!OperatingSystem.IsWindows() || processId <= 0)
            return false;

        var targetProcess = OpenProcess(ProcessQueryLimitedInformation, inheritHandle: false, processId);
        if (targetProcess == IntPtr.Zero)
            return false;

        IntPtr currentToken = IntPtr.Zero;
        IntPtr targetToken = IntPtr.Zero;
        IntPtr currentUserBuffer = IntPtr.Zero;
        IntPtr targetUserBuffer = IntPtr.Zero;

        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out currentToken) ||
                !OpenProcessToken(targetProcess, TokenQuery, out targetToken))
            {
                return false;
            }

            var currentSid = ReadTokenUserSid(currentToken, out currentUserBuffer);
            var targetSid = ReadTokenUserSid(targetToken, out targetUserBuffer);
            return currentSid != IntPtr.Zero &&
                targetSid != IntPtr.Zero &&
                EqualSid(currentSid, targetSid);
        }
        finally
        {
            if (currentUserBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(currentUserBuffer);
            if (targetUserBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(targetUserBuffer);
            if (currentToken != IntPtr.Zero)
                CloseHandle(currentToken);
            if (targetToken != IntPtr.Zero)
                CloseHandle(targetToken);
            CloseHandle(targetProcess);
        }
    }

    private static IntPtr ReadTokenUserSid(IntPtr tokenHandle, out IntPtr buffer)
    {
        buffer = IntPtr.Zero;
        _ = GetTokenInformation(
            tokenHandle,
            TokenUserInformationClass,
            IntPtr.Zero,
            0,
            out var requiredLength);
        if (requiredLength <= 0)
            return IntPtr.Zero;

        buffer = Marshal.AllocHGlobal(requiredLength);
        if (!GetTokenInformation(
                tokenHandle,
                TokenUserInformationClass,
                buffer,
                requiredLength,
                out _))
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
            return IntPtr.Zero;
        }

        return Marshal.PtrToStructure<TokenUser>(buffer).User.Sid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenUser
    {
        public SidAndAttributes User;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EqualSid(IntPtr sid1, IntPtr sid2);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}