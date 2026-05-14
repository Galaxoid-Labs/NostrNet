// SPDX-License-Identifier: MIT
//
// The relay seam used by NostrMarmotClient. Publishing an event and
// subscribing to filters are the only operations Marmot needs out of
// a Nostr relay; abstracting them as an interface (with a concrete
// NostrClient-backed adapter) keeps the high-level client testable
// without spinning up a real WebSocket relay.

using System.Runtime.CompilerServices;
using NostrNet.Client;
using NostrNet.Events;
using NostrNet.Relay;

namespace NostrNet.Marmot;

/// <summary>
/// The relay operations <see cref="NostrMarmotClient"/> depends on.
/// Implemented by <see cref="NostrClientMarmotRelay"/> for production
/// use; tests can supply a fake.
/// </summary>
public interface IMarmotRelay
{
    /// <summary>
    /// Publishes <paramref name="ev"/> to the bound relays. Throws if every
    /// relay rejected the event; succeeds if at least one accepted.
    /// </summary>
    Task PublishAsync(NostrEvent ev, CancellationToken ct = default);

    /// <summary>
    /// Subscribes with the given <paramref name="filters"/> and yields each
    /// event as it arrives. The stream stays open until
    /// <paramref name="ct"/> is cancelled.
    /// </summary>
    IAsyncEnumerable<NostrEvent> SubscribeAsync(
        IReadOnlyList<Filter> filters,
        CancellationToken ct = default);
}

/// <summary>
/// <see cref="IMarmotRelay"/> adapter backed by a real
/// <see cref="NostrClient"/>. Pass an already-connected client to the
/// constructor and hand the adapter to <see cref="NostrMarmotClient"/>.
/// </summary>
public sealed class NostrClientMarmotRelay : IMarmotRelay
{
    private readonly NostrClient _client;

    /// <summary>Wraps an existing <see cref="NostrClient"/> as an <see cref="IMarmotRelay"/>.</summary>
    public NostrClientMarmotRelay(NostrClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
    }

    /// <inheritdoc/>
    public async Task PublishAsync(NostrEvent ev, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(ev);
        var results = await _client.PublishAsync(ev, ct).ConfigureAwait(false);
        if (results.Count == 0)
        {
            throw new InvalidOperationException(
                "Publish returned no relay results — is the client connected to any relays?");
        }

        bool anyAccepted = false;
        foreach (var r in results.Values)
        {
            if (r.Accepted)
            {
                anyAccepted = true;
                break;
            }
        }

        if (!anyAccepted)
        {
            var reasons = string.Join("; ", results
                .Select(kv => $"{kv.Key}: {(string.IsNullOrEmpty(kv.Value.Message) ? "rejected" : kv.Value.Message)}"));
            throw new InvalidOperationException($"Event publish was rejected by every relay. {reasons}");
        }
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<NostrEvent> SubscribeAsync(
        IReadOnlyList<Filter> filters,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(filters);
        await foreach (var received in _client.SubscribeAsync(filters, ct).ConfigureAwait(false))
        {
            yield return received.Event;
        }
    }
}
