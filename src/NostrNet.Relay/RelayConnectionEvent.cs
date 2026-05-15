// SPDX-License-Identifier: MIT

namespace NostrNet.Relay;

/// <summary>
/// Lifecycle state of a single relay connection, as surfaced by
/// <see cref="RelayPool.ObserveConnectionsAsync"/>.
/// </summary>
public enum RelayConnectionState
{
    /// <summary>A connect attempt is in progress (initial or reconnect).</summary>
    Connecting,

    /// <summary>The WebSocket handshake completed; the relay is ready.</summary>
    Connected,

    /// <summary>
    /// The connection is closed or has failed. See
    /// <see cref="RelayConnectionEvent.Reason"/> for why.
    /// </summary>
    Disconnected,
}

/// <summary>Why a relay connection ended.</summary>
public enum RelayDisconnectReason
{
    /// <summary>Not disconnected (used for <see cref="RelayConnectionState.Connecting"/> and <see cref="RelayConnectionState.Connected"/> events).</summary>
    None,

    /// <summary>The owner explicitly disposed the client or pool. Terminal — no reconnect is attempted.</summary>
    Disposed,

    /// <summary>An initial or retry connect attempt failed (handshake error, DNS, TCP refused, etc.).</summary>
    ConnectFailed,

    /// <summary>The transport (WebSocket / TCP) errored after being open.</summary>
    TransportError,

    /// <summary>The remote relay initiated a normal close.</summary>
    ServerClosed,
}

/// <summary>
/// One state-change notification for a single relay connection. Yielded by
/// <see cref="RelayPool.ObserveConnectionsAsync"/> and
/// <c>NostrClient.ObserveRelayConnectionsAsync</c>.
/// </summary>
/// <param name="Relay">The relay URI this event is about.</param>
/// <param name="State">The new state.</param>
/// <param name="Reason">For <see cref="RelayConnectionState.Disconnected"/>, why the connection ended. <see cref="RelayDisconnectReason.None"/> otherwise.</param>
/// <param name="Error">For transport errors and connect failures, the underlying exception. Null for clean transitions.</param>
/// <param name="AttemptNumber">1 for the initial connect, incremented on each reconnect attempt. Useful for "retrying… (attempt N)" UI.</param>
public sealed record RelayConnectionEvent(
    Uri Relay,
    RelayConnectionState State,
    RelayDisconnectReason Reason,
    Exception? Error,
    int AttemptNumber);
