// SPDX-License-Identifier: MIT

using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Relay;

/// <summary>
/// Abstraction over a single-relay client connection. Exposed primarily for
/// testability (fakes/mocks in caller code).
/// </summary>
public interface IRelayClient : IAsyncDisposable
{
    /// <summary>The URI of the relay this client is connected to, or null if not connected.</summary>
    Uri? Uri { get; }

    /// <summary><c>true</c> if the underlying WebSocket is currently open.</summary>
    bool IsConnected { get; }

    /// <summary>Opens the WebSocket connection to a relay.</summary>
    Task ConnectAsync(Uri uri, CancellationToken cancellationToken = default);

    /// <summary>
    /// Publishes a signed event and awaits the relay's <c>OK</c> response.
    /// </summary>
    /// <returns>The relay's accept/reject decision with a human-readable message.</returns>
    Task<PublishResult> PublishAsync(NostrEvent ev, CancellationToken cancellationToken = default);

    /// <summary>
    /// Opens a subscription with the given id and filters. The returned stream
    /// yields <see cref="SubscriptionEventReceived"/> messages, one
    /// <see cref="SubscriptionEndOfStoredEvents"/> when stored events have all
    /// been delivered, and terminates when the subscription is closed (locally
    /// via <see cref="CloseAsync"/>, by the relay, or by cancellation).
    /// </summary>
    IAsyncEnumerable<SubscriptionEvent> SubscribeAsync(
        string subscriptionId,
        IReadOnlyList<Filter> filters,
        CancellationToken cancellationToken = default);

    /// <summary>Closes a subscription on the relay side.</summary>
    Task CloseAsync(string subscriptionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// The most recent NIP-42 <c>AUTH</c> challenge received from this relay,
    /// or <c>null</c> if none has been sent yet. Replaced if a new challenge
    /// arrives.
    /// </summary>
    string? LatestAuthChallenge { get; }

    /// <summary>
    /// Signs and sends a NIP-42 auth event using <paramref name="key"/>, then
    /// awaits the relay's <c>OK</c> response. Uses
    /// <see cref="LatestAuthChallenge"/> as the challenge.
    /// </summary>
    /// <exception cref="InvalidOperationException">No AUTH challenge has been received yet.</exception>
    Task<PublishResult> AuthenticateAsync(PrivateKey key, CancellationToken cancellationToken = default);

    /// <summary>
    /// When set, the client automatically responds to any NIP-42 <c>AUTH</c>
    /// challenge from this relay using this key. Set to <c>null</c> to
    /// disable auto-auth. Auto-auth runs as a fire-and-forget background
    /// task; failures are silently swallowed.
    /// </summary>
    /// <remarks>
    /// When <see cref="AutoAuthKey"/> is non-null, <see cref="PublishAsync"/>
    /// also transparently retries (once) on <c>auth-required</c> rejections,
    /// awaiting the in-flight AUTH first.
    /// </remarks>
    PrivateKey? AutoAuthKey { get; set; }

    /// <summary>
    /// Awaits the most recent in-flight auto-AUTH attempt, if any. Returns
    /// immediately if no auto-auth is in progress. Used by higher layers
    /// (e.g. <c>RelayPool</c>) that want to wait for AUTH before resuming a
    /// rejected operation.
    /// </summary>
    Task WaitForAuthAsync(CancellationToken cancellationToken = default);
}
