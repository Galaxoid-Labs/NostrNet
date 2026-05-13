// SPDX-License-Identifier: MIT

using NostrNet.Events;

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
}
