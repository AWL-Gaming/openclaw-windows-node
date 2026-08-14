using System.Net;

namespace OpenClaw.Connection.Tests;

public sealed class WindowsTcpListenerSnapshotTests
{
    [Fact]
    public void CurrentProcess_IsOwnedByCurrentUser()
    {
        if (!OperatingSystem.IsWindows())
            return;

        Assert.True(WindowsProcessOwnership.IsOwnedByCurrentUser(Environment.ProcessId));
    }
    [Fact]
    public void LoopbackOwner_AllowsExactIpv4LoopbackListenerOwnedByCurrentUser()
    {
        var snapshot = Snapshot(
            new WindowsTcpListenerInfo(IPAddress.Loopback, 18792, 321, "node", null));

        Assert.True(WindowsTcpListenerSnapshot.IsLoopbackListenerOwnedByCurrentUser(
            snapshot,
            18792,
            processId => processId == 321));
    }

    [Fact]
    public void LoopbackOwner_RejectsWildcardListener()
    {
        var snapshot = Snapshot(
            new WindowsTcpListenerInfo(IPAddress.Any, 18792, 321, "node", null));

        Assert.False(WindowsTcpListenerSnapshot.IsLoopbackListenerOwnedByCurrentUser(
            snapshot,
            18792,
            _ => true));
    }

    [Fact]
    public void LoopbackOwner_RejectsDifferentUser()
    {
        var snapshot = Snapshot(
            new WindowsTcpListenerInfo(IPAddress.Loopback, 18792, 321, "node", null));

        Assert.False(WindowsTcpListenerSnapshot.IsLoopbackListenerOwnedByCurrentUser(
            snapshot,
            18792,
            _ => false));
    }

    [Fact]
    public void LoopbackOwner_RejectsIncompleteIpv4Snapshot()
    {
        var snapshot = new WindowsTcpListenerSnapshotResult(
            [new WindowsTcpListenerInfo(IPAddress.Loopback, 18792, 321, "node", null)],
            Ipv4Complete: false,
            Ipv6Complete: true);

        Assert.False(WindowsTcpListenerSnapshot.IsLoopbackListenerOwnedByCurrentUser(
            snapshot,
            18792,
            _ => true));
    }

    [Fact]
    public void LoopbackOwner_RejectsDifferentPort()
    {
        var snapshot = Snapshot(
            new WindowsTcpListenerInfo(IPAddress.Loopback, 18792, 321, "node", null));

        Assert.False(WindowsTcpListenerSnapshot.IsLoopbackListenerOwnedByCurrentUser(
            snapshot,
            18791,
            _ => true));
    }

    private static WindowsTcpListenerSnapshotResult Snapshot(params WindowsTcpListenerInfo[] listeners) =>
        new(listeners, Ipv4Complete: true, Ipv6Complete: true);
}