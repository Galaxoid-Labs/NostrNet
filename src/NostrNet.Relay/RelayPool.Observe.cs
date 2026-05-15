// SPDX-License-Identifier: MIT
//
// Per-relay connection observation + auto-reconnect for RelayPool.
//
// Strategy:
//   - Each concrete RelayClient the pool owns gets its internal StateChanged
//     callback wired to HandleStateChanged. The pool stamps in URI + attempt
//     number and produces a public RelayConnectionEvent.
//   - Last-known state per URI is cached so newly-arriving observers see a
//     snapshot before live events.
//   - Observers are independent channels in a fan-out list. Each is removed
//     when its iterator cancels or the pool disposes.
//   - On Disconnected with a non-Disposed reason, ScheduleReconnect kicks off
//     a backoff loop that builds a fresh RelayClient, swaps it into _clients,
//     and retries until success or pool dispose.

using System.Runtime.CompilerServices;
using System.Threading.Channels;

namespace NostrNet.Relay;

public sealed partial class RelayPool
{
    private readonly object _observeLock = new();
    private readonly List<Channel<RelayConnectionEvent>> _observers = new();
    private readonly Dictionary<Uri, RelayConnectionEvent> _lastStates = new();
    private readonly Dictionary<Uri, int> _attemptCounters = new();
    private readonly Dictionary<Uri, Task> _reconnectTasks = new();
    private readonly List<ReconnectWaiter> _reconnectWaiters = new();
    private CancellationTokenSource? _observeCts;

    private sealed record ReconnectWaiter(Uri Uri, TaskCompletionSource<IRelayClient> Tcs);

    // Exponential backoff schedule used by reconnect. Capped at 30s.
    private static readonly TimeSpan[] BackoffSchedule =
    {
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(2),
        TimeSpan.FromSeconds(4),
        TimeSpan.FromSeconds(8),
        TimeSpan.FromSeconds(16),
        TimeSpan.FromSeconds(30),
    };

    /// <summary>
    /// Yields per-relay connection state changes as they happen. On subscribe,
    /// emits one event per relay currently known to the pool (the snapshot)
    /// before yielding live transitions.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Multi-consumer: each call creates an independent channel, so two UI
    /// surfaces can observe the same pool without stealing events from each
    /// other.
    /// </para>
    /// <para>
    /// The stream completes when <paramref name="cancellationToken"/> fires
    /// or the pool is disposed.
    /// </para>
    /// <para>
    /// Reconnect (when <see cref="AutoReconnect"/> is on) emits
    /// <c>Connecting → Connected</c> on success or
    /// <c>Connecting → Disconnected(ConnectFailed)</c> per attempt, with
    /// <see cref="RelayConnectionEvent.AttemptNumber"/> incrementing so UI
    /// can render "retrying… (attempt N)".
    /// </para>
    /// </remarks>
    public async IAsyncEnumerable<RelayConnectionEvent> ObserveConnectionsAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();

        var channel = Channel.CreateUnbounded<RelayConnectionEvent>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false,
        });

        RelayConnectionEvent[] snapshot;
        lock (_observeLock)
        {
            // Take the snapshot under the same lock that gates additions,
            // so we don't miss a transition between snapshot and registration.
            snapshot = _lastStates.Values.ToArray();
            _observers.Add(channel);
        }

        try
        {
            foreach (var ev in snapshot)
            {
                yield return ev;
            }

            await foreach (var ev in channel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                yield return ev;
            }
        }
        finally
        {
            lock (_observeLock)
            {
                _observers.Remove(channel);
            }

            channel.Writer.TryComplete();
        }
    }

    private RelayClient NewObservedClient(Uri uri)
    {
        var client = new RelayClient();
        AttachStateCallback(uri, client);
        return client;
    }

    private void AttachStateCallback(Uri uri, RelayClient client)
    {
        client.StateChanged = (state, reason, error) =>
            HandleStateChanged(uri, state, reason, error);
    }

    private void HandleStateChanged(
        Uri uri,
        RelayConnectionState state,
        RelayDisconnectReason reason,
        Exception? error)
    {
        if (_disposed == 1)
        {
            return;
        }

        Channel<RelayConnectionEvent>[] observers;
        int attempt;
        RelayConnectionEvent ev;

        lock (_observeLock)
        {
            // Increment attempt count on each Connecting transition. The
            // initial connect is attempt 1; the first reconnect is 2; etc.
            if (state == RelayConnectionState.Connecting)
            {
                attempt = _attemptCounters.TryGetValue(uri, out int prev) ? prev + 1 : 1;
                _attemptCounters[uri] = attempt;
            }
            else
            {
                attempt = _attemptCounters.TryGetValue(uri, out int prev) ? prev : 1;
            }

            ev = new RelayConnectionEvent(uri, state, reason, error, attempt);
            _lastStates[uri] = ev;
            observers = _observers.ToArray();
        }

        foreach (var ch in observers)
        {
            ch.Writer.TryWrite(ev);
        }

        // Complete any subscribe pumps waiting for this URI to come back.
        if (state == RelayConnectionState.Connected)
        {
            ReconnectWaiter[] toComplete;
            IRelayClient? newClient;
            lock (_observeLock)
            {
                toComplete = _reconnectWaiters.Where(w => w.Uri == uri).ToArray();
                foreach (var w in toComplete)
                {
                    _reconnectWaiters.Remove(w);
                }
            }

            lock (_clients)
            {
                _clients.TryGetValue(uri, out newClient);
            }

            foreach (var w in toComplete)
            {
                if (newClient is not null)
                {
                    w.Tcs.TrySetResult(newClient);
                }
                else
                {
                    w.Tcs.TrySetException(new InvalidOperationException(
                        $"Relay {uri} was removed from the pool."));
                }
            }
        }

        // Trigger reconnect AFTER fan-out, so observers see the Disconnected
        // event before the subsequent Connecting.
        if (state == RelayConnectionState.Disconnected
            && reason != RelayDisconnectReason.Disposed
            && AutoReconnect
            && _disposed != 1)
        {
            ScheduleReconnect(uri);
        }
    }

    /// <summary>
    /// Returns a task that completes with the latest <see cref="IRelayClient"/>
    /// for <paramref name="uri"/> the next time the pool observes a
    /// <see cref="RelayConnectionState.Connected"/> transition for it. Used by
    /// <see cref="SubscribeAsync"/> to bridge transient transport drops when
    /// <see cref="AutoResubscribe"/> is enabled.
    /// </summary>
    internal Task<IRelayClient> WaitForReconnectAsync(Uri uri, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<IRelayClient>(TaskCreationOptions.RunContinuationsAsynchronously);
        var waiter = new ReconnectWaiter(uri, tcs);

        lock (_observeLock)
        {
            if (_disposed == 1)
            {
                tcs.TrySetException(new ObjectDisposedException(nameof(RelayPool)));
                return tcs.Task;
            }

            _reconnectWaiters.Add(waiter);
        }

        if (ct.CanBeCanceled)
        {
            var registration = ct.Register(static state =>
            {
                var (pool, w) = ((RelayPool, ReconnectWaiter))state!;
                lock (pool._observeLock)
                {
                    pool._reconnectWaiters.Remove(w);
                }

                w.Tcs.TrySetCanceled();
            }, (this, waiter));

            // Make sure the CT registration is disposed once the task is settled,
            // so we don't leak per-pump callbacks across many reconnect cycles.
            tcs.Task.ContinueWith(
                static (_, reg) => ((CancellationTokenRegistration)reg!).Dispose(),
                registration,
                TaskContinuationOptions.ExecuteSynchronously);
        }

        return tcs.Task;
    }

    private void ScheduleReconnect(Uri uri)
    {
        // _observeCts is the parent for all reconnect tasks; created lazily
        // on first need and torn down by ShutdownObservation in DisposeAsync.
        CancellationToken token;
        lock (_observeLock)
        {
            if (_disposed == 1)
            {
                return;
            }

            _observeCts ??= new CancellationTokenSource();
            token = _observeCts.Token;

            // If a reconnect task is already running for this URI, don't
            // start a second one. The existing loop handles retries.
            if (_reconnectTasks.TryGetValue(uri, out var existing) && !existing.IsCompleted)
            {
                return;
            }

            var task = Task.Run(() => ReconnectLoopAsync(uri, token), CancellationToken.None);
            _reconnectTasks[uri] = task;
        }
    }

    private async Task ReconnectLoopAsync(Uri uri, CancellationToken token)
    {
        int retryIndex = 0;

        while (!token.IsCancellationRequested && _disposed != 1)
        {
            var delay = BackoffSchedule[Math.Min(retryIndex, BackoffSchedule.Length - 1)];
            try
            {
                await Task.Delay(delay, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            if (token.IsCancellationRequested || _disposed == 1)
            {
                return;
            }

            var client = NewObservedClient(uri);
            try
            {
                await client.ConnectAsync(uri, token).ConfigureAwait(false);
                client.AutoAuthKey = _autoAuthKey;
                lock (_clients)
                {
                    if (_disposed == 1)
                    {
                        // Pool was disposed during the reconnect; drop the
                        // freshly-built client and bail.
                        _ = client.DisposeAsync().AsTask();
                        return;
                    }

                    _clients[uri] = client;
                }

                // Connected emission already fired from RelayClient.ConnectAsync.
                return;
            }
            catch (OperationCanceledException)
            {
                await client.DisposeAsync().ConfigureAwait(false);
                return;
            }
            catch
            {
                // RelayClient already emitted Disconnected(ConnectFailed).
                await client.DisposeAsync().ConfigureAwait(false);
                retryIndex++;
                // continue the loop with a longer delay
            }
        }
    }

    private void ShutdownObservation()
    {
        CancellationTokenSource? cts;
        Channel<RelayConnectionEvent>[] observers;
        ReconnectWaiter[] waiters;

        lock (_observeLock)
        {
            cts = _observeCts;
            _observeCts = null;
            observers = _observers.ToArray();
            _observers.Clear();
            waiters = _reconnectWaiters.ToArray();
            _reconnectWaiters.Clear();
        }

        cts?.Cancel();
        cts?.Dispose();

        foreach (var ch in observers)
        {
            ch.Writer.TryComplete();
        }

        foreach (var w in waiters)
        {
            w.Tcs.TrySetException(new ObjectDisposedException(nameof(RelayPool)));
        }
    }
}
