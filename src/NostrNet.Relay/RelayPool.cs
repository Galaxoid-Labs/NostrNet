// SPDX-License-Identifier: MIT

using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using NostrNet.Auth;
using NostrNet.Events;

namespace NostrNet.Relay;

/// <summary>
/// A pool of <see cref="IRelayClient"/> instances. Publishes fan out across
/// all relays (per-relay results are returned); subscriptions merge into a
/// single deduplicated stream.
/// </summary>
public sealed partial class RelayPool : IAsyncDisposable
{
    private readonly Dictionary<Uri, IRelayClient> _clients = new();
    private Keys.PrivateKey? _autoAuthKey;
    private int _disposed;

    /// <summary>
    /// When <c>true</c> (the default), the pool transparently re-establishes
    /// a relay connection after a transport error or server-side close, using
    /// exponential backoff (1s → 30s cap). State transitions are surfaced via
    /// <see cref="ObserveConnectionsAsync"/>. Set to <c>false</c> if your app
    /// wants to drive reconnect itself.
    /// </summary>
    public bool AutoReconnect { get; set; } = true;

    /// <summary>
    /// When <c>true</c> (the default), in-flight <see cref="SubscribeAsync"/>
    /// calls transparently re-issue their REQ on the relay after a reconnect.
    /// The caller's <see cref="IAsyncEnumerable{T}"/> keeps yielding events
    /// from the new connection without surfacing a
    /// <see cref="SubscriptionClosed"/> for the transient drop.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Has no effect when <see cref="AutoReconnect"/> is <c>false</c> — there's
    /// no reconnect to resume over.
    /// </para>
    /// <para>
    /// Filters are re-issued as-supplied. If your filter uses <c>Since</c> or
    /// <c>Limit</c>, you'll likely see overlap with events received before the
    /// drop — pair with an event store (which auto-dedups) for live feeds.
    /// </para>
    /// <para>
    /// Per-call opt-out: not needed. One-shot fetches (the caller breaks out
    /// of the <c>await foreach</c> or cancels its <see cref="CancellationToken"/>)
    /// don't trigger resume because the pump cancels with the caller.
    /// </para>
    /// </remarks>
    public bool AutoResubscribe { get; set; } = true;

    /// <summary>The URIs of the relays currently in the pool.</summary>
    public IReadOnlyCollection<Uri> Uris
    {
        get { lock (_clients) { return _clients.Keys.ToArray(); } }
    }

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
            var client = NewObservedClient(uri);
            try
            {
                await client.ConnectAsync(uri, cancellationToken).ConfigureAwait(false);
                client.AutoAuthKey = _autoAuthKey;   // pick up current auto-auth
                lock (_clients)
                {
                    _clients[uri] = client;
                }
            }
            catch (Exception ex)
            {
                failures[uri] = ex;
                await client.DisposeAsync().ConfigureAwait(false);
                // Note: RelayClient already emitted Disconnected(ConnectFailed)
                // via its StateChanged callback; ObserveConnectionsAsync sees it.
                // We still surface failures via the return dictionary for
                // callers who want a one-shot snapshot.
                if (AutoReconnect)
                {
                    ScheduleReconnect(uri);
                }
            }
        }).ToArray();

        await Task.WhenAll(connectTasks).ConfigureAwait(false);
        return failures;
    }

    /// <summary>
    /// Adds an already-connected client to the pool. If auto-auth is
    /// configured on the pool, it's propagated to the new client.
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

        client.AutoAuthKey = _autoAuthKey;

        // If the caller handed us a concrete RelayClient, hook its state
        // callback for observation + reconnect. Foreign IRelayClient impls
        // (test fakes) don't get state observation — that's acceptable
        // because they're under caller control.
        if (client is RelayClient rc)
        {
            AttachStateCallback(uri, rc);
            // Synthesize a Connected event for the existing connection so
            // observers see this relay in their snapshot.
            if (rc.IsConnected)
            {
                HandleStateChanged(uri, RelayConnectionState.Connected, RelayDisconnectReason.None, null);
            }
        }
    }

    /// <summary>
    /// Sets (or clears, when <paramref name="key"/> is null) the auto-auth
    /// key used by every client in the pool. <c>NostrClient</c> calls this
    /// when its key state changes; most consumers don't need to call it.
    /// </summary>
    public void SetAutoAuthKey(Keys.PrivateKey? key)
    {
        EnsureNotDisposed();
        _autoAuthKey = key;

        IRelayClient[] snapshot;
        lock (_clients)
        {
            snapshot = _clients.Values.ToArray();
        }

        foreach (var client in snapshot)
        {
            client.AutoAuthKey = key;
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
    /// Sends a NIP-42 AUTH response on every relay in the pool that has
    /// received a challenge. Relays without a pending challenge are skipped
    /// (no entry in the result for them).
    /// </summary>
    /// <param name="key">The key used to sign the auth events.</param>
    /// <param name="cancellationToken">Cancels in-flight AUTHs.</param>
    /// <returns>Per-relay OK responses for the relays that were authenticated.</returns>
    public async Task<IReadOnlyDictionary<Uri, PublishResult>> AuthenticateAllAsync(
        Keys.PrivateKey key,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        EnsureNotDisposed();

        (Uri uri, IRelayClient client)[] toAuth;
        lock (_clients)
        {
            toAuth = _clients
                .Where(kvp => kvp.Value.LatestAuthChallenge is not null)
                .Select(kvp => (kvp.Key, kvp.Value))
                .ToArray();
        }

        var tasks = new Task<PublishResult>[toAuth.Length];
        for (int i = 0; i < toAuth.Length; i++)
        {
            int captured = i;
            tasks[i] = SafeAuth(toAuth[captured].client, key, cancellationToken);
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);

        var results = new Dictionary<Uri, PublishResult>(toAuth.Length);
        for (int i = 0; i < toAuth.Length; i++)
        {
            results[toAuth[i].uri] = tasks[i].Result;
        }

        return results;
    }

    private static async Task<PublishResult> SafeAuth(IRelayClient client, Keys.PrivateKey key, CancellationToken ct)
    {
        try
        {
            return await client.AuthenticateAsync(key, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return new PublishResult(false, $"auth transport error: {ex.Message}");
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

        (Uri uri, IRelayClient client)[] snapshot;
        lock (_clients)
        {
            snapshot = _clients.Select(kvp => (kvp.Key, kvp.Value)).ToArray();
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

        int eoseCount = 0;
        int closedCount = 0;
        int totalRelays = snapshot.Length;

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        var pumpTasks = snapshot.Select(entry => Task.Run(async () =>
        {
            Uri uri = entry.uri;
            IRelayClient client = entry.client;

            // Per-relay retry counter; capped so an unresolvable auth-required
            // (e.g. our key isn't on the relay's allow-list) doesn't loop.
            int authRetries = 0;
            const int MaxAuthRetries = 1;

            // Captured across iterations of the resubscribe loop so the
            // terminal SubscriptionClosed (if any) surfaces the relay's last
            // reason rather than a stale "connection closed".
            string? finalReason = null;

            while (true)
            {
                bool retryAfterAuth = false;
                bool transportDrop = false;

                try
                {
                    await foreach (var ev in client.SubscribeAsync(subscriptionId, filters, linked.Token).ConfigureAwait(false))
                    {
                        // Transparent re-subscribe on auth-required when
                        // auto-auth is configured.
                        if (ev is SubscriptionClosed cl
                            && client.AutoAuthKey is not null
                            && authRetries < MaxAuthRetries
                            && Nip42.IsAuthRequired(cl.Reason))
                        {
                            retryAfterAuth = true;
                            authRetries++;
                            break;
                        }

                        switch (ev)
                        {
                            case SubscriptionEventReceived received:
                                await merged.Writer.WriteAsync(received, linked.Token).ConfigureAwait(false);
                                break;

                            case SubscriptionEndOfStoredEvents:
                                if (Interlocked.Increment(ref eoseCount) == totalRelays)
                                {
                                    await merged.Writer.WriteAsync(new SubscriptionEndOfStoredEvents(), linked.Token).ConfigureAwait(false);
                                }

                                break;

                            case SubscriptionClosed closed:
                                finalReason = closed.Reason;
                                break;
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    // Caller is leaving. Don't count this as a relay close for
                    // the merged stream — match the pre-resubscribe behavior.
                    return;
                }
                catch
                {
                    transportDrop = true;
                }

                if (retryAfterAuth)
                {
                    try
                    {
                        await client.WaitForAuthAsync(linked.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                    catch
                    {
                        // Auth task itself failed; try the re-subscribe anyway —
                        // it'll likely just fail again and the retry cap stops the loop.
                    }

                    continue;
                }

                if (linked.Token.IsCancellationRequested)
                {
                    return;
                }

                // If the inner foreach exited cleanly and the WebSocket is
                // still open, the relay sent a server-side CLOSED — this pump
                // is terminal. Otherwise the transport dropped underneath us
                // (catch-all above, or the receive loop's finally emitted
                // SubscriptionClosed("connection closed") and IsConnected has
                // flipped to false).
                if (!transportDrop && client.IsConnected)
                {
                    break;
                }

                if (!AutoResubscribe || !AutoReconnect)
                {
                    break;
                }

                // Wait for the pool's reconnect machinery to bring this relay
                // back, then reissue REQ on the fresh RelayClient instance.
                IRelayClient next;
                try
                {
                    next = await WaitForReconnectAsync(uri, linked.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch
                {
                    // Pool disposed or relay removed. Terminal.
                    break;
                }

                client = next;
                authRetries = 0;
                finalReason = null;
            }

            if (Interlocked.Increment(ref closedCount) == totalRelays)
            {
                await merged.Writer.WriteAsync(
                    new SubscriptionClosed(finalReason ?? "connection closed"),
                    linked.Token).ConfigureAwait(false);
                merged.Writer.TryComplete();
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

        // Cancel any in-flight reconnect tasks and signal observers to complete.
        ShutdownObservation();

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
