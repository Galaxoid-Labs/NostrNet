// SPDX-License-Identifier: MIT

using System.Buffers;
using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading.Channels;
using NostrNet.Events;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Relay;

/// <summary>
/// A single-relay WebSocket client implementing NIP-01 messaging.
/// </summary>
/// <remarks>
/// Lifecycle: construct → <see cref="ConnectAsync"/> → use → <see cref="DisposeAsync"/>.
/// One instance manages one connection. Publish and subscribe operations are
/// thread-safe; multiple concurrent calls are supported.
/// </remarks>
public sealed class RelayClient : IRelayClient
{
    private readonly ClientWebSocket _webSocket = new();
    private readonly Channel<string> _outgoing = Channel.CreateUnbounded<string>(new UnboundedChannelOptions
    {
        SingleReader = true,
        SingleWriter = false,
        AllowSynchronousContinuations = false,
    });

    private readonly ConcurrentDictionary<string, Channel<SubscriptionEvent>> _subscriptions = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource<PublishResult>> _pendingPublishes = new();

    private CancellationTokenSource? _runCts;
    private Task? _sendTask;
    private Task? _receiveTask;
    private Uri? _uri;
    private int _state; // 0=new, 1=connecting, 2=connected, 3=disposed

    /// <inheritdoc/>
    public Uri? Uri => _uri;

    /// <inheritdoc/>
    public bool IsConnected => _state == 2 && _webSocket.State == WebSocketState.Open;

    /// <inheritdoc/>
    public async Task ConnectAsync(Uri uri, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);
        int prev = Interlocked.CompareExchange(ref _state, 1, 0);
        if (prev != 0)
        {
            throw new InvalidOperationException("RelayClient has already been connected or disposed.");
        }

        await _webSocket.ConnectAsync(uri, cancellationToken).ConfigureAwait(false);
        _uri = uri;

        _runCts = new CancellationTokenSource();
        _sendTask = Task.Run(() => SendLoopAsync(_runCts.Token), CancellationToken.None);
        _receiveTask = Task.Run(() => ReceiveLoopAsync(_runCts.Token), CancellationToken.None);

        Interlocked.Exchange(ref _state, 2);
    }

    /// <inheritdoc/>
    public async Task<PublishResult> PublishAsync(NostrEvent ev, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ev);
        EnsureConnected();

        var tcs = new TaskCompletionSource<PublishResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        string idHex = ev.Id.ToHex();

        if (!_pendingPublishes.TryAdd(idHex, tcs))
        {
            throw new InvalidOperationException($"A publish for event id {idHex} is already in flight.");
        }

        await _outgoing.Writer.WriteAsync(RelayProtocol.BuildPublishMessage(ev), cancellationToken).ConfigureAwait(false);

        using (cancellationToken.Register(state =>
        {
            var t = (TaskCompletionSource<PublishResult>)state!;
            t.TrySetCanceled();
        }, tcs))
        {
            try
            {
                return await tcs.Task.ConfigureAwait(false);
            }
            finally
            {
                _pendingPublishes.TryRemove(idHex, out _);
            }
        }
    }

    /// <inheritdoc/>
    public async IAsyncEnumerable<SubscriptionEvent> SubscribeAsync(
        string subscriptionId,
        IReadOnlyList<Filter> filters,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subscriptionId);
        ArgumentNullException.ThrowIfNull(filters);
        EnsureConnected();

        var channel = Channel.CreateUnbounded<SubscriptionEvent>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true,
            AllowSynchronousContinuations = false,
        });

        if (!_subscriptions.TryAdd(subscriptionId, channel))
        {
            throw new InvalidOperationException($"Subscription '{subscriptionId}' already exists.");
        }

        await _outgoing.Writer.WriteAsync(
            RelayProtocol.BuildSubscribeMessage(subscriptionId, filters),
            cancellationToken).ConfigureAwait(false);

        try
        {
            await foreach (var msg in channel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
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
            _subscriptions.TryRemove(subscriptionId, out _);
            // Best-effort: notify the relay if the connection is still open.
            if (IsConnected)
            {
                try
                {
                    await _outgoing.Writer.WriteAsync(
                        RelayProtocol.BuildCloseMessage(subscriptionId),
                        CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                    // Swallow — connection may be tearing down.
                }
            }
        }
    }

    /// <inheritdoc/>
    public async Task CloseAsync(string subscriptionId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subscriptionId);
        EnsureConnected();

        if (_subscriptions.TryGetValue(subscriptionId, out var channel))
        {
            channel.Writer.TryComplete();
        }

        await _outgoing.Writer.WriteAsync(
            RelayProtocol.BuildCloseMessage(subscriptionId),
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _state, 3) == 3)
        {
            return;
        }

        _runCts?.Cancel();
        _outgoing.Writer.TryComplete();

        foreach (var sub in _subscriptions.Values)
        {
            sub.Writer.TryComplete();
        }

        foreach (var pub in _pendingPublishes.Values)
        {
            pub.TrySetCanceled();
        }

        try
        {
            if (_webSocket.State == WebSocketState.Open)
            {
                await _webSocket.CloseAsync(
                    WebSocketCloseStatus.NormalClosure,
                    "client disposing",
                    CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch
        {
            // Connection may already be closed; swallow.
        }

        try
        {
            if (_sendTask is not null)
            {
                await _sendTask.ConfigureAwait(false);
            }
        }
        catch
        {
            // Send loop exit is best-effort during dispose.
        }

        try
        {
            if (_receiveTask is not null)
            {
                await _receiveTask.ConfigureAwait(false);
            }
        }
        catch
        {
            // Receive loop exit is best-effort during dispose.
        }

        _webSocket.Dispose();
        _runCts?.Dispose();
    }

    private void EnsureConnected()
    {
        if (_state == 3)
        {
            throw new ObjectDisposedException(nameof(RelayClient));
        }

        if (_state != 2)
        {
            throw new InvalidOperationException("RelayClient is not connected. Call ConnectAsync first.");
        }
    }

    private async Task SendLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await foreach (string message in _outgoing.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                if (_webSocket.State != WebSocketState.Open)
                {
                    break;
                }

                byte[] bytes = SysEncoding.UTF8.GetBytes(message);
                await _webSocket.SendAsync(
                    bytes,
                    WebSocketMessageType.Text,
                    endOfMessage: true,
                    cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Cancellation is expected during shutdown.
        }
        catch (WebSocketException)
        {
            // Connection lost; receive loop will surface this.
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        // Per-frame receive buffer (pooled). Working in bytes throughout
        // avoids two UTF-8 round-trips per frame; the assembled message is
        // parsed by JsonDocument directly from the underlying bytes.
        byte[] receiveBuffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        var pending = new ArrayBufferWriter<byte>(initialCapacity: 64 * 1024);

        try
        {
            while (!cancellationToken.IsCancellationRequested
                && _webSocket.State == WebSocketState.Open)
            {
                var result = await _webSocket.ReceiveAsync(receiveBuffer, cancellationToken).ConfigureAwait(false);
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    break;
                }

                if (result.MessageType != WebSocketMessageType.Text)
                {
                    continue;
                }

                pending.Write(receiveBuffer.AsSpan(0, result.Count));
                if (!result.EndOfMessage)
                {
                    continue;
                }

                RelayMessage? message = null;
                try
                {
                    using var doc = JsonDocument.Parse(pending.WrittenMemory);
                    message = RelayMessage.Parse(doc.RootElement);
                }
                catch (Exception ex) when (ex is JsonException or FormatException)
                {
                    // Malformed message — ignore and keep reading.
                }
                finally
                {
                    pending.ResetWrittenCount();
                }

                if (message is not null)
                {
                    Dispatch(message);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Expected during dispose.
        }
        catch (WebSocketException)
        {
            // Connection lost. Surface to subscribers below.
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(receiveBuffer);

            // Connection is over. Tell every pending subscriber.
            foreach (var sub in _subscriptions)
            {
                sub.Value.Writer.TryWrite(new SubscriptionClosed("connection closed"));
                sub.Value.Writer.TryComplete();
            }

            foreach (var pub in _pendingPublishes)
            {
                pub.Value.TrySetException(new IOException("Relay connection closed before OK was received."));
            }
        }
    }

    private void Dispatch(RelayMessage message)
    {
        switch (message)
        {
            case EventMessage ev:
                // Verify id + signature before surfacing. A malicious or
                // misbehaving relay could otherwise inject bogus events into
                // a subscription. Invalid events are dropped silently — the
                // receive loop continues reading the next message.
                if (!ev.Event.Verify())
                {
                    break;
                }

                if (_subscriptions.TryGetValue(ev.SubscriptionId, out var subEv))
                {
                    // _uri is set inside ConnectAsync before the receive
                    // loop ever starts, so it's non-null here.
                    subEv.Writer.TryWrite(new SubscriptionEventReceived(ev.Event, _uri!));
                }

                break;

            case EndOfStoredEventsMessage eose:
                if (_subscriptions.TryGetValue(eose.SubscriptionId, out var subEose))
                {
                    subEose.Writer.TryWrite(new SubscriptionEndOfStoredEvents());
                }

                break;

            case OkMessage ok:
                if (_pendingPublishes.TryRemove(ok.EventId, out var pubTcs))
                {
                    pubTcs.TrySetResult(new PublishResult(ok.Accepted, ok.Message));
                }

                break;

            case ClosedMessage closed:
                if (_subscriptions.TryRemove(closed.SubscriptionId, out var subClosed))
                {
                    subClosed.Writer.TryWrite(new SubscriptionClosed(closed.Reason));
                    subClosed.Writer.TryComplete();
                }

                break;

            case NoticeMessage:
            case AuthChallengeMessage:
                // Surface via events on a future revision; for v1 these are
                // observed at the protocol layer but not threaded through the
                // public API.
                break;
        }
    }
}
