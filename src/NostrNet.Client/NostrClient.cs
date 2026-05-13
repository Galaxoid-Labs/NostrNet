// SPDX-License-Identifier: MIT

using System.Runtime.CompilerServices;
using NostrNet.Crypto;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Relay;

namespace NostrNet.Client;

/// <summary>
/// High-level convenience client: owns a <see cref="RelayPool"/> and a
/// <see cref="PrivateKey"/>, exposes ergonomic helpers for the most common
/// Nostr operations (post a note, send a DM, subscribe to your own feed).
/// </summary>
/// <remarks>
/// Construct via <see cref="Builder"/>:
/// <code>
/// await using var client = await NostrClient.Builder(privateKey)
///     .UseRelays("wss://relay.damus.io", "wss://nos.lol")
///     .ConnectAsync();
/// await client.PostNoteAsync("hello!");
/// </code>
/// </remarks>
public sealed class NostrClient : IAsyncDisposable
{
    private readonly PrivateKey _key;
    private readonly RelayPool _pool;
    private bool _ownsPool;
    private bool _disposed;

    internal NostrClient(PrivateKey key, RelayPool pool, bool ownsPool)
    {
        _key = key;
        _pool = pool;
        _ownsPool = ownsPool;
    }

    /// <summary>Begins fluent construction of a client bound to <paramref name="key"/>.</summary>
    public static NostrClientBuilder Builder(PrivateKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new NostrClientBuilder(key);
    }

    /// <summary>The client's public key.</summary>
    public PublicKey PublicKey => _key.PublicKey;

    /// <summary>The relays currently in the pool.</summary>
    public IReadOnlyCollection<Uri> Relays => _pool.Uris;

    /// <summary>
    /// Publishes a pre-signed event to all relays in the pool.
    /// </summary>
    public Task<IReadOnlyDictionary<Uri, PublishResult>> PublishAsync(
        NostrEvent ev,
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        return _pool.PublishAsync(ev, cancellationToken);
    }

    /// <summary>
    /// Signs and publishes a kind-1 text note containing <paramref name="content"/>.
    /// </summary>
    public async Task<IReadOnlyDictionary<Uri, PublishResult>> PostNoteAsync(
        string content,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        EnsureNotDisposed();

        var ev = new UnsignedEvent
        {
            PubKey = _key.PublicKey,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = content,
        }.Sign(_key);

        return await _pool.PublishAsync(ev, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a NIP-17 direct message to <paramref name="recipient"/>.
    /// </summary>
    /// <remarks>
    /// The plaintext is wrapped per NIP-17/NIP-59 (rumor → seal → gift wrap)
    /// using the client's private key and an ephemeral key for the outer wrap.
    /// </remarks>
    public async Task<IReadOnlyDictionary<Uri, PublishResult>> SendDirectMessageAsync(
        PublicKey recipient,
        string content,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(recipient);
        ArgumentNullException.ThrowIfNull(content);
        EnsureNotDisposed();

        NostrEvent giftWrap = Nip17.CreateDirectMessage(content, _key, recipient);
        return await _pool.PublishAsync(giftWrap, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Subscribes with the given filters and yields every matching event.
    /// </summary>
    public async IAsyncEnumerable<NostrEvent> SubscribeAsync(
        IReadOnlyList<Filter> filters,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filters);
        EnsureNotDisposed();

        string subscriptionId = "sub-" + Guid.NewGuid().ToString("N")[..16];
        await foreach (var msg in _pool.SubscribeAsync(subscriptionId, filters, cancellationToken).ConfigureAwait(false))
        {
            if (msg is SubscriptionEventReceived received)
            {
                yield return received.Event;
            }
            else if (msg is SubscriptionClosed)
            {
                yield break;
            }
        }
    }

    /// <summary>
    /// Subscribes to text notes (kind 1) optionally narrowed to <paramref name="authors"/>.
    /// </summary>
    public IAsyncEnumerable<NostrEvent> SubscribeNotesAsync(
        IReadOnlyList<PublicKey>? authors = null,
        int? limit = null,
        CancellationToken cancellationToken = default)
    {
        var filter = new Filter
        {
            Kinds = new[] { 1 },
            Authors = authors?.Select(a => a.ToHex()).ToArray(),
            Limit = limit,
        };

        return SubscribeAsync(new[] { filter }, cancellationToken);
    }

    /// <summary>
    /// Subscribes to NIP-17 direct messages addressed to this client.
    /// Each yielded message is fully unwrapped (gift wrap, seal, rumor) and
    /// includes the verified sender.
    /// </summary>
    /// <remarks>
    /// Gift wraps that fail to decrypt or verify are silently skipped — this
    /// is normal during operation (other recipients' messages, malformed
    /// payloads, etc.).
    /// </remarks>
    public async IAsyncEnumerable<UnwrappedDirectMessage> SubscribeDirectMessagesAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();

        var filter = new Filter
        {
            Kinds = new[] { Nip17.GiftWrapKind },
            TagFilters = new Dictionary<string, IReadOnlyList<string>>
            {
                ["p"] = new[] { _key.PublicKey.ToHex() },
            },
        };

        await foreach (var ev in SubscribeAsync(new[] { filter }, cancellationToken).ConfigureAwait(false))
        {
            UnwrappedDirectMessage? unwrapped = null;
            try
            {
                unwrapped = Nip17.Unwrap(ev, _key);
            }
            catch
            {
                // Not for us, or malformed. Skip.
            }

            if (unwrapped is not null)
            {
                yield return unwrapped;
            }
        }
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_ownsPool)
        {
            await _pool.DisposeAsync().ConfigureAwait(false);
        }
    }

    private void EnsureNotDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(NostrClient));
        }
    }
}

/// <summary>Fluent builder for <see cref="NostrClient"/>.</summary>
public sealed class NostrClientBuilder
{
    private readonly PrivateKey _key;
    private readonly List<Uri> _relays = new();

    internal NostrClientBuilder(PrivateKey key)
    {
        _key = key;
    }

    /// <summary>Adds relay URIs from string form.</summary>
    public NostrClientBuilder UseRelays(params string[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);
        foreach (string u in uris)
        {
            _relays.Add(new Uri(u));
        }

        return this;
    }

    /// <summary>Adds relay URIs.</summary>
    public NostrClientBuilder UseRelays(params Uri[] uris)
    {
        ArgumentNullException.ThrowIfNull(uris);
        _relays.AddRange(uris);
        return this;
    }

    /// <summary>Connects to all configured relays and returns the ready client.</summary>
    public async Task<NostrClient> ConnectAsync(CancellationToken cancellationToken = default)
    {
        if (_relays.Count == 0)
        {
            throw new InvalidOperationException("At least one relay must be configured before connecting.");
        }

        var pool = new RelayPool();
        try
        {
            await pool.ConnectAsync(_relays, cancellationToken).ConfigureAwait(false);
            return new NostrClient(_key, pool, ownsPool: true);
        }
        catch
        {
            await pool.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}
