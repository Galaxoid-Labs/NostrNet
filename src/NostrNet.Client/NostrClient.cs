// SPDX-License-Identifier: MIT

using System.Runtime.CompilerServices;
using NostrNet.Crypto;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Relay;

namespace NostrNet.Client;

/// <summary>
/// High-level convenience client: owns a <see cref="RelayPool"/> and optionally
/// a <see cref="PrivateKey"/>, exposes ergonomic helpers for the most common
/// Nostr operations (post a note, send a DM, subscribe to a feed).
/// </summary>
/// <remarks>
/// <para>
/// Construct with a key for the full feature set:
/// </para>
/// <code>
/// await using var client = await NostrClient.Builder(privateKey)
///     .UseRelays("wss://relay.damus.io", "wss://nos.lol")
///     .ConnectAsync();
/// await client.PostNoteAsync("hello!");
/// </code>
///
/// <para>
/// Or construct without a key for read-only browsing — subscriptions and
/// pre-signed publishes work, but anything that needs to sign or decrypt
/// (post, send DM, subscribe to your own DMs) throws
/// <see cref="InvalidOperationException"/>. Check <see cref="HasKey"/> before
/// calling those.
/// </para>
/// <code>
/// await using var client = await NostrClient.Builder()
///     .UseRelays("wss://relay.damus.io")
///     .ConnectAsync();
/// await foreach (var note in client.SubscribeNotesAsync(limit: 100))
///     Console.WriteLine(note.Content);
/// </code>
///
/// <para>
/// A key can be attached later via <see cref="SetKey"/> (and detached via
/// <see cref="ClearKey"/>) without recreating the relay connections —
/// useful for "connect first, sign in later" flows.
/// </para>
/// </remarks>
public sealed class NostrClient : IAsyncDisposable
{
    private PrivateKey? _key;
    private readonly RelayPool _pool;
    private readonly bool _ownsPool;
    private bool _disposed;

    internal NostrClient(PrivateKey? key, RelayPool pool, bool ownsPool)
    {
        _key = key;
        _pool = pool;
        _ownsPool = ownsPool;
    }

    /// <summary>
    /// Attaches a private key to this client. Allows graduating an anonymous
    /// client to a signing one without recreating the relay connections —
    /// useful for "connect first, sign in later" flows.
    /// </summary>
    /// <remarks>
    /// In-flight subscriptions and publishes captured the previous key at
    /// their start and continue with it; only subsequent calls see the new
    /// key. The client does not take ownership of the key — the caller is
    /// responsible for its lifetime (typically via <c>using</c> /
    /// <c>Dispose</c>) and must not dispose it while the client still uses it.
    /// </remarks>
    public void SetKey(PrivateKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        EnsureNotDisposed();
        _key = key;
    }

    /// <summary>
    /// Detaches the current private key. Subsequent calls to signing- or
    /// decryption-dependent methods will throw. Existing subscriptions and
    /// publishes that captured the previous key continue unaffected.
    /// </summary>
    /// <remarks>
    /// Does not dispose the key — the caller owns its lifetime. Combine
    /// with <c>key.Dispose()</c> if you want to zero the secret as well.
    /// </remarks>
    public void ClearKey()
    {
        EnsureNotDisposed();
        _key = null;
    }

    /// <summary>
    /// Begins fluent construction of a read-only client (no signing key).
    /// Subscribe and publish-pre-signed work; posting and DM helpers throw.
    /// </summary>
    public static NostrClientBuilder Builder() => new(key: null);

    /// <summary>
    /// Begins fluent construction of a client bound to <paramref name="key"/>.
    /// Enables every helper including <see cref="PostNoteAsync"/>,
    /// <see cref="SendDirectMessageAsync"/>, and
    /// <see cref="SubscribeDirectMessagesAsync"/>.
    /// </summary>
    public static NostrClientBuilder Builder(PrivateKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return new NostrClientBuilder(key);
    }

    /// <summary>
    /// True if this client was constructed with a private key. When false,
    /// signing- or decryption-dependent methods throw.
    /// </summary>
    public bool HasKey => _key is not null;

    /// <summary>
    /// The client's public key, or <c>null</c> if the client was constructed
    /// without a key.
    /// </summary>
    public PublicKey? PublicKey => _key?.PublicKey;

    /// <summary>The relays currently in the pool.</summary>
    public IReadOnlyCollection<Uri> Relays => _pool.Uris;

    /// <summary>
    /// Sends a NIP-42 AUTH response on every relay that has issued a
    /// challenge, using this client's key. Relays without a pending
    /// challenge are skipped.
    /// </summary>
    /// <exception cref="InvalidOperationException">The client was constructed without a key.</exception>
    public Task<IReadOnlyDictionary<Uri, PublishResult>> AuthenticateAllAsync(
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        var key = RequireKey(nameof(AuthenticateAllAsync));
        return _pool.AuthenticateAllAsync(key, cancellationToken);
    }

    /// <summary>
    /// Publishes a pre-signed event to all relays in the pool. Does not
    /// require this client to have a key — the event is already signed.
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
    /// <exception cref="InvalidOperationException">The client was constructed without a key.</exception>
    public async Task<IReadOnlyDictionary<Uri, PublishResult>> PostNoteAsync(
        string content,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        EnsureNotDisposed();
        var key = RequireKey(nameof(PostNoteAsync));

        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = content,
        }.Sign(key);

        return await _pool.PublishAsync(ev, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends a NIP-17 direct message to <paramref name="recipient"/>.
    /// </summary>
    /// <remarks>
    /// The plaintext is wrapped per NIP-17/NIP-59 (rumor → seal → gift wrap)
    /// using the client's private key and an ephemeral key for the outer wrap.
    /// </remarks>
    /// <exception cref="InvalidOperationException">The client was constructed without a key.</exception>
    public async Task<IReadOnlyDictionary<Uri, PublishResult>> SendDirectMessageAsync(
        PublicKey recipient,
        string content,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(recipient);
        ArgumentNullException.ThrowIfNull(content);
        EnsureNotDisposed();
        var key = RequireKey(nameof(SendDirectMessageAsync));

        NostrEvent giftWrap = Nip17.CreateDirectMessage(content, key, recipient);
        return await _pool.PublishAsync(giftWrap, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Subscribes with the given filters and yields each event as it arrives,
    /// tagged with the relay that delivered it. Works without a key.
    /// </summary>
    /// <remarks>
    /// When multiple relays carry the same event, each delivery is yielded
    /// separately — the consumer decides whether to dedup. For a feed-style
    /// "each event once" experience, dedup on <c>received.Event.Id</c> in
    /// the loop. For relay-coverage analysis, keep all occurrences.
    /// </remarks>
    public async IAsyncEnumerable<ReceivedEvent> SubscribeAsync(
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
                yield return new ReceivedEvent(received.Event, received.Relay);
            }
            else if (msg is SubscriptionClosed)
            {
                yield break;
            }
        }
    }

    /// <summary>
    /// Subscribes to text notes (kind 1) optionally narrowed to
    /// <paramref name="authors"/>. Works without a key.
    /// </summary>
    /// <remarks>
    /// Each yielded <see cref="ReceivedEvent"/> carries the originating
    /// relay. Multiple relays may deliver the same note — see
    /// <see cref="SubscribeAsync"/>.
    /// </remarks>
    public IAsyncEnumerable<ReceivedEvent> SubscribeNotesAsync(
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
    /// <exception cref="InvalidOperationException">The client was constructed without a key.</exception>
    public async IAsyncEnumerable<UnwrappedDirectMessage> SubscribeDirectMessagesAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        var key = RequireKey(nameof(SubscribeDirectMessagesAsync));

        var filter = new Filter
        {
            Kinds = new[] { Nip17.GiftWrapKind },
            TagFilters = new Dictionary<string, IReadOnlyList<string>>
            {
                ["p"] = new[] { key.PublicKey.ToHex() },
            },
        };

        await foreach (var received in SubscribeAsync(new[] { filter }, cancellationToken).ConfigureAwait(false))
        {
            UnwrappedDirectMessage? unwrapped = null;
            try
            {
                unwrapped = Nip17.Unwrap(received.Event, key) with { Relay = received.Relay };
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

    private PrivateKey RequireKey(string operation)
    {
        if (_key is null)
        {
            throw new InvalidOperationException(
                $"{operation} requires a private key. Construct the client with NostrClient.Builder(privateKey).");
        }

        return _key;
    }
}

/// <summary>Fluent builder for <see cref="NostrClient"/>.</summary>
public sealed class NostrClientBuilder
{
    private readonly PrivateKey? _key;
    private readonly List<Uri> _relays = new();

    internal NostrClientBuilder(PrivateKey? key)
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
