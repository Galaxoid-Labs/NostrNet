// SPDX-License-Identifier: MIT

using System.Runtime.CompilerServices;
using NostrNet.Crypto;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Pictures;
using NostrNet.Relay;
using NostrNet.Reposts;
using NostrNet.UserStatuses;

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
    private bool _autoAuth;
    private bool _disposed;

    internal NostrClient(PrivateKey? key, RelayPool pool, bool ownsPool, bool autoAuth)
    {
        _key = key;
        _pool = pool;
        _ownsPool = ownsPool;
        _autoAuth = autoAuth;
        SyncAutoAuth();
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
        SyncAutoAuth();
    }

    /// <summary>
    /// The currently-attached signing key, or <c>null</c> if the client
    /// was built without one (read-only mode). Exposed so add-on
    /// packages (e.g. <c>NostrNet.Blossom</c>) can reuse the same key
    /// for protocol-specific event signing without round-tripping
    /// through the client's helper methods.
    /// </summary>
    public PrivateKey? SigningKey => _key;

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
        SyncAutoAuth();
    }

    /// <summary>
    /// When <c>true</c> (the default), the client automatically responds to
    /// any NIP-42 <c>AUTH</c> challenge from a connected relay using the
    /// current key. Set to <c>false</c> to opt out; you can still call
    /// <see cref="AuthenticateAllAsync"/> manually.
    /// </summary>
    /// <remarks>
    /// Auto-auth is best-effort and fire-and-forget — if the relay rejects
    /// the AUTH event, the failure is silently swallowed. For visibility,
    /// disable auto-auth and call <see cref="AuthenticateAllAsync"/> when
    /// you want a result.
    /// </remarks>
    public bool AutoAuth
    {
        get => _autoAuth;
        set
        {
            EnsureNotDisposed();
            _autoAuth = value;
            SyncAutoAuth();
        }
    }

    private void SyncAutoAuth() => _pool.SetAutoAuthKey(_autoAuth ? _key : null);

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
    /// Signs and publishes a NIP-68 kind-20 picture-first event.
    /// <paramref name="attachments"/> becomes one <c>imeta</c> tag per
    /// image and must contain at least one entry. <paramref name="title"/>
    /// is the required short title; <paramref name="description"/> is the
    /// free-text caption (event content). Build a richer event — content
    /// warnings, hashtags, location, language, tagged users — via
    /// <see cref="PictureEvent.Create"/> and call
    /// <see cref="PublishAsync"/> directly.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="attachments"/> is empty.</exception>
    /// <exception cref="InvalidOperationException">The client was constructed without a key.</exception>
    public async Task<IReadOnlyDictionary<Uri, PublishResult>> PostPictureAsync(
        string title,
        string description,
        IReadOnlyList<PictureMediaAttachment> attachments,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(title);
        ArgumentNullException.ThrowIfNull(description);
        ArgumentNullException.ThrowIfNull(attachments);
        if (attachments.Count == 0)
        {
            throw new ArgumentException("At least one attachment is required for a NIP-68 picture event.", nameof(attachments));
        }

        EnsureNotDisposed();
        var key = RequireKey(nameof(PostPictureAsync));

        var builder = PictureEvent.Create(title).WithDescription(description);
        foreach (var attachment in attachments)
        {
            builder.AddAttachment(attachment);
        }

        var ev = builder.BuildAndSign(key);
        return await _pool.PublishAsync(ev, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reposts <paramref name="originalEvent"/> per NIP-18. The kind
    /// is chosen automatically: kind 6 for kind-1 originals, kind 16
    /// for anything else. The original event is embedded as JSON in
    /// the repost's content field by default — pass an explicit
    /// <see cref="RepostEvent.Create"/> builder + <c>EmbedOriginal(false)</c>
    /// to opt out (e.g. for NIP-70 protected originals).
    /// </summary>
    /// <exception cref="InvalidOperationException">The client was constructed without a key.</exception>
    public async Task<IReadOnlyDictionary<Uri, PublishResult>> RepostAsync(
        NostrEvent originalEvent,
        string? relayHint = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(originalEvent);
        EnsureNotDisposed();
        var key = RequireKey(nameof(RepostAsync));

        var builder = RepostEvent.Create(originalEvent);
        if (relayHint is not null)
        {
            builder.WithRelayHint(relayHint);
        }

        return await _pool.PublishAsync(builder.BuildAndSign(key), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Posts a NIP-18 quote-repost: a regular kind-1 note containing
    /// <paramref name="comment"/> as content plus a <c>q</c> tag
    /// referencing <paramref name="quotedEvent"/>. The <c>q</c> tag —
    /// instead of an <c>e</c> tag — keeps the quote out of the
    /// quoted event's reply thread.
    /// </summary>
    /// <exception cref="InvalidOperationException">The client was constructed without a key.</exception>
    public async Task<IReadOnlyDictionary<Uri, PublishResult>> QuoteRepostAsync(
        string comment,
        NostrEvent quotedEvent,
        string? relayHint = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(comment);
        ArgumentNullException.ThrowIfNull(quotedEvent);
        EnsureNotDisposed();
        var key = RequireKey(nameof(QuoteRepostAsync));

        // Per NIP-18, only include the pubkey on the q-tag for regular
        // (non-replaceable) events. Kinds 30000-39999 + replaceable
        // ranges are coordinate-addressed; for those we keep the
        // pubkey omitted so consumers know to dereference via the
        // 'a' tag form (which a future overload can carry).
        bool isRegularEvent = quotedEvent.Kind is < 10000 or >= 40000;
        var q = Repost.QuoteTag(
            quotedEvent.Id,
            relayHint,
            isRegularEvent ? quotedEvent.PubKey : null);

        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = 1,
            Tags = new IReadOnlyList<string>[] { q },
            Content = comment,
        }.Sign(key);

        return await _pool.PublishAsync(ev, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Publishes a NIP-38 user-status update (kind 30315) under the
    /// given <paramref name="type"/> slot (e.g.
    /// <see cref="UserStatusTypes.General"/> or
    /// <see cref="UserStatusTypes.Music"/>). The event replaces any
    /// prior status of the same type for this pubkey on cooperating
    /// relays. Pass an empty <paramref name="content"/> to clear the
    /// slot.
    /// </summary>
    /// <exception cref="InvalidOperationException">The client was constructed without a key.</exception>
    public async Task<IReadOnlyDictionary<Uri, PublishResult>> PublishUserStatusAsync(
        string type,
        string content,
        DateTimeOffset? expiration = null,
        string? referenceUrl = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(type);
        ArgumentNullException.ThrowIfNull(content);
        EnsureNotDisposed();
        var key = RequireKey(nameof(PublishUserStatusAsync));

        var builder = UserStatus.Create(type).WithContent(content);
        if (expiration is DateTimeOffset exp) builder.WithExpiration(exp);
        if (referenceUrl is not null) builder.WithReference(referenceUrl);

        return await _pool.PublishAsync(builder.BuildAndSign(key), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Convenience: publishes an empty-content NIP-38 event for the
    /// given <paramref name="type"/> slot. Per spec, an empty status
    /// signals "clear" — clients that render statuses should drop
    /// the slot's value when they see this event.
    /// </summary>
    public Task<IReadOnlyDictionary<Uri, PublishResult>> ClearUserStatusAsync(
        string type,
        CancellationToken cancellationToken = default)
        => PublishUserStatusAsync(type, string.Empty, cancellationToken: cancellationToken);

    /// <summary>
    /// Fetches the most recent NIP-38 status of the given
    /// <paramref name="type"/> for <paramref name="owner"/>. Returns
    /// <c>null</c> when no kind-30315 event was returned before
    /// <paramref name="timeout"/> elapsed. Expired statuses are
    /// returned as-is — callers should check
    /// <see cref="UserStatus.HasExpired"/> if they want to filter.
    /// </summary>
    public async Task<UserStatus?> TryGetUserStatusAsync(
        PublicKey owner,
        string type,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentException.ThrowIfNullOrEmpty(type);
        EnsureNotDisposed();

        var filter = new Filter
        {
            Kinds = new[] { Nip38Kinds.UserStatus },
            Authors = new[] { owner.ToHex() },
            TagFilters = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["d"] = new[] { type },
            },
            Limit = 1,
        };

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout ?? TimeSpan.FromSeconds(5));

        UserStatus? best = null;
        try
        {
            await foreach (var received in SubscribeAsync(new[] { filter }, cts.Token).ConfigureAwait(false))
            {
                if (!UserStatus.TryFromEvent(received.Event, out var parsed) || parsed is null)
                {
                    continue;
                }

                if (parsed.Type != type || !parsed.Author.Equals(owner))
                {
                    continue;
                }

                if (best is null || parsed.CreatedAt > best.CreatedAt)
                {
                    best = parsed;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Timeout — return whatever we collected.
        }

        return best;
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
    private bool _autoAuth = true;

    internal NostrClientBuilder(PrivateKey? key)
    {
        _key = key;
    }

    /// <summary>
    /// Enables (default) or disables automatic NIP-42 AUTH responses. When
    /// enabled and the client has a key, every <c>AUTH</c> challenge from a
    /// connected relay is answered in the background.
    /// </summary>
    public NostrClientBuilder WithAutoAuth(bool enabled)
    {
        _autoAuth = enabled;
        return this;
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
            return new NostrClient(_key, pool, ownsPool: true, _autoAuth);
        }
        catch
        {
            await pool.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}
