// SPDX-License-Identifier: MIT

using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using NostrNet.Events;

namespace NostrNet.Relay;

/// <summary>
/// A pool of <see cref="IRelayClient"/> instances. Publishes fan out across
/// all relays (per-relay results are returned); subscriptions merge into a
/// single deduplicated stream.
/// </summary>
public sealed class RelayPool : IAsyncDisposable
{
    private readonly Dictionary<Uri, IRelayClient> _clients = new();
    private int _disposed;

    /// <summary>The URIs of the relays currently in the pool.</summary>
    public IReadOnlyCollection<Uri> Uris => _clients.Keys;

    /// <summary>
    /// Connects to all relays in parallel. Failed individual connections do
    /// not abort the pool; the resulting dictionary's value is null for any
    /// relay that failed to connect.
    /// </summary>
    /// <returns>A map from relay URI to <see cref="Exception"/> for the relays whose connection failed. Empty if all succeeded.</returns>
    public async Task<IReadOnlyDictionary<Uri, Exception>> ConnectAsync(
        IReadOnlyList<Uri> uris,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uris);
        EnsureNotDisposed();

        var failures = new ConcurrentDictionary<Uri, Exception>();
        var connectTasks = uris.Select(async uri =>
        {
            var client = new RelayClient();
            try
            {
                await client.ConnectAsync(uri, cancellationToken).ConfigureAwait(false);
                lock (_clients)
                {
                    _clients[uri] = client;
                }
            }
            catch (Exception ex)
            {
                failures[uri] = ex;
                await client.DisposeAsync().ConfigureAwait(false);
            }
        }).ToArray();

        await Task.WhenAll(connectTasks).ConfigureAwait(false);
        return failures;
    }

    /// <summary>
    /// Adds an already-connected client to the pool.
    /// </summary>
    public void Add(Uri uri, IRelayClient client)
    {
        ArgumentNullException.ThrowIfNull(uri);
        ArgumentNullException.ThrowIfNull(client);
        EnsureNotDisposed();
        lock (_clients)
        {
            _clients[uri] = client;
        }
    }

    /// <summary>
    /// Publishes an event to every relay in the pool and returns the per-relay
    /// outcomes.
    /// </summary>
    public async Task<IReadOnlyDictionary<Uri, PublishResult>> PublishAsync(
        NostrEvent ev,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ev);
        EnsureNotDisposed();

        IRelayClient[] snapshot;
        Uri[] uriSnapshot;
        lock (_clients)
        {
            snapshot = _clients.Values.ToArray();
            uriSnapshot = _clients.Keys.ToArray();
        }

        var tasks = new Task<PublishResult>[snapshot.Length];
        for (int i = 0; i < snapshot.Length; i++)
        {
            int captured = i;
            tasks[i] = SafePublish(snapshot[captured], ev, cancellationToken);
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);

        var results = new Dictionary<Uri, PublishResult>(snapshot.Length);
        for (int i = 0; i < snapshot.Length; i++)
        {
            results[uriSnapshot[i]] = tasks[i].Result;
        }

        return results;
    }

    private static async Task<PublishResult> SafePublish(IRelayClient client, NostrEvent ev, CancellationToken ct)
    {
        try
        {
            return await client.PublishAsync(ev, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return new PublishResult(false, $"transport error: {ex.Message}");
        }
    }

    /// <summary>
    /// Subscribes on every relay in the pool. The returned stream is the union
    /// of all relays' streams, deduplicated by event id. A single
    /// <see cref="SubscriptionEndOfStoredEvents"/> is yielded once every relay
    /// has signaled EOSE; a single <see cref="SubscriptionClosed"/> is yielded
    /// once every relay has closed.
    /// </summary>
    public async IAsyncEnumerable<SubscriptionEvent> SubscribeAsync(
        string subscriptionId,
        IReadOnlyList<Filter> filters,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subscriptionId);
        ArgumentNullException.ThrowIfNull(filters);
        EnsureNotDisposed();

        IRelayClient[] snapshot;
        lock (_clients)
        {
            snapshot = _clients.Values.ToArray();
        }

        if (snapshot.Length == 0)
        {
            yield break;
        }

        var merged = Channel.CreateUnbounded<SubscriptionEvent>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false,
        });

        var seen = new ConcurrentDictionary<string, byte>();
        int eoseCount = 0;
        int closedCount = 0;
        int totalRelays = snapshot.Length;

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        var pumpTasks = snapshot.Select(client => Task.Run(async () =>
        {
            try
            {
                await foreach (var ev in client.SubscribeAsync(subscriptionId, filters, linked.Token).ConfigureAwait(false))
                {
                    switch (ev)
                    {
                        case SubscriptionEventReceived received:
                            if (seen.TryAdd(received.Event.Id.ToHex(), 0))
                            {
                                await merged.Writer.WriteAsync(received, linked.Token).ConfigureAwait(false);
                            }

                            break;

                        case SubscriptionEndOfStoredEvents:
                            if (Interlocked.Increment(ref eoseCount) == totalRelays)
                            {
                                await merged.Writer.WriteAsync(new SubscriptionEndOfStoredEvents(), linked.Token).ConfigureAwait(false);
                            }

                            break;

                        case SubscriptionClosed closed:
                            if (Interlocked.Increment(ref closedCount) == totalRelays)
                            {
                                await merged.Writer.WriteAsync(new SubscriptionClosed(closed.Reason), linked.Token).ConfigureAwait(false);
                                merged.Writer.TryComplete();
                            }

                            break;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Caller cancelled or pool disposing — clean exit.
            }
            catch (Exception)
            {
                // Treat any per-relay failure as a close for that relay's contribution.
                if (Interlocked.Increment(ref closedCount) == totalRelays)
                {
                    merged.Writer.TryComplete();
                }
            }
        }, linked.Token)).ToArray();

        try
        {
            await foreach (var msg in merged.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                yield return msg;
                if (msg is SubscriptionClosed)
                {
                    yield break;
                }
            }
        }
        finally
        {
            linked.Cancel();
            try
            {
                await Task.WhenAll(pumpTasks).ConfigureAwait(false);
            }
            catch
            {
                // Pump tasks may throw due to cancellation; safe to ignore.
            }
        }
    }

    /// <summary>Sends CLOSE for the given subscription on every relay.</summary>
    public async Task CloseAsync(string subscriptionId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subscriptionId);
        EnsureNotDisposed();

        IRelayClient[] snapshot;
        lock (_clients)
        {
            snapshot = _clients.Values.ToArray();
        }

        var tasks = snapshot.Select(c => SafeClose(c, subscriptionId, cancellationToken)).ToArray();
        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private static async Task SafeClose(IRelayClient client, string subId, CancellationToken ct)
    {
        try
        {
            await client.CloseAsync(subId, ct).ConfigureAwait(false);
        }
        catch
        {
            // Best-effort.
        }
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
        {
            return;
        }

        IRelayClient[] toDispose;
        lock (_clients)
        {
            toDispose = _clients.Values.ToArray();
            _clients.Clear();
        }

        var tasks = toDispose.Select(c => c.DisposeAsync().AsTask()).ToArray();
        try
        {
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch
        {
            // Dispose is best-effort.
        }
    }

    private void EnsureNotDisposed()
    {
        if (_disposed == 1)
        {
            throw new ObjectDisposedException(nameof(RelayPool));
        }
    }
}
