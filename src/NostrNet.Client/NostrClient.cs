// SPDX-License-Identifier: MIT

using System.Runtime.CompilerServices;
using NostrNet.Badges;
using NostrNet.Crypto;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Pictures;
using NostrNet.Relay;
using NostrNet.Relay.Storage;
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
    private readonly INostrEventStore? _eventStore;
    private bool _autoAuth;
    private bool _disposed;

    internal NostrClient(
        PrivateKey? key,
        RelayPool pool,
        bool ownsPool,
        bool autoAuth,
        INostrEventStore? eventStore)
    {
        _key = key;
        _pool = pool;
        _ownsPool = ownsPool;
        _autoAuth = autoAuth;
        _eventStore = eventStore;
        SyncAutoAuth();
    }

    /// <summary>
    /// The attached <see cref="INostrEventStore"/>, if one was configured
    /// via <see cref="NostrClientBuilder.WithEventStore"/>; otherwise
    /// <c>null</c>. When non-null:
    /// <list type="bullet">
    ///   <item><see cref="SubscribeAsync"/> auto-dedups using the store —
    ///         events already known are not yielded a second time even when
    ///         multiple relays deliver them.</item>
    ///   <item>Prefer <see cref="AttachAsync"/> + the store's
    ///         <c>QueryAsync</c> / <c>ObserveAsync</c> for UI feeds:
    ///         events flow once into the store and the UI reads from
    ///         there instead of iterating the raw stream.</item>
    /// </list>
    /// </summary>
    public INostrEventStore? EventStore => _eventStore;

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
    /// Issues a NIP-50 full-text search across the configured relays.
    /// Yields each matching event as it arrives. <paramref name="query"/>
    /// is sent verbatim in the filter's <c>search</c> field — embed
    /// modifier pairs (<c>include:spam</c>, <c>domain:nip05.host</c>,
    /// etc.) as space-separated tokens.
    /// </summary>
    /// <param name="query">Free-form search string. May contain NIP-50 modifiers.</param>
    /// <param name="kinds">Optional event kinds to constrain the search; most relays cap unconstrained search-only queries.</param>
    /// <param name="authors">Optional pubkey hex filter (use this for "search this user's posts").</param>
    /// <param name="limit">Max stored events to return (per relay).</param>
    /// <param name="cancellationToken">Cancels the subscription / stream.</param>
    /// <remarks>
    /// Only relays that advertise NIP-50 in their NIP-11 document honor
    /// the search field; others may return their default-filter result
    /// set (e.g. every kind-1 note). Use
    /// <see cref="RelayInformation.SupportsSearch"/> to gate the call.
    /// </remarks>
    public IAsyncEnumerable<ReceivedEvent> SearchAsync(
        string query,
        IReadOnlyList<int>? kinds = null,
        IReadOnlyList<PublicKey>? authors = null,
        int? limit = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(query);
        EnsureNotDisposed();

        var filter = new Filter
        {
            Search = query,
            Kinds = kinds,
            Authors = authors?.Select(a => a.ToHex()).ToArray(),
            Limit = limit,
        };

        return SubscribeAsync(new[] { filter }, cancellationToken);
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

    // ────────────────────────────────────────────────────────────
    // NIP-58 badges
    // ────────────────────────────────────────────────────────────

    /// <summary>
    /// Publishes a NIP-58 Badge Definition (kind 30009) under the
    /// given <paramref name="identifier"/>. Returns the published
    /// <see cref="BadgeDefinition"/> so callers have the address
    /// string ready for awarding.
    /// </summary>
    public async Task<BadgeDefinition> PublishBadgeDefinitionAsync(
        string identifier,
        string? name = null,
        string? description = null,
        string? imageUrl = null,
        string? imageDim = null,
        IEnumerable<(string Url, string? Dim)>? thumbnails = null,
        int powDifficulty = 0,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);
        if (powDifficulty < 0) throw new ArgumentOutOfRangeException(nameof(powDifficulty));
        EnsureNotDisposed();
        var key = RequireKey(nameof(PublishBadgeDefinitionAsync));

        var builder = BadgeDefinition.Create(identifier);
        if (name is not null) builder.WithName(name);
        if (description is not null) builder.WithDescription(description);
        if (imageUrl is not null) builder.WithImage(imageUrl, imageDim);
        if (thumbnails is not null)
        {
            foreach (var (url, dim) in thumbnails) builder.AddThumbnail(url, dim);
        }

        // NIP-58 lets issuers embed NIP-13 PoW to give the definition
        // a verifiable "minting cost." Skip the cost when difficulty is 0.
        var ev = powDifficulty > 0
            ? builder.BuildMineAndSign(key, powDifficulty, cancellationToken)
            : builder.BuildAndSign(key);
        await _pool.PublishAsync(ev, cancellationToken).ConfigureAwait(false);
        return BadgeDefinition.FromEvent(ev);
    }

    /// <summary>
    /// Publishes a NIP-58 Badge Award (kind 8) for the given badge
    /// to one or more recipients. The signer (the client's identity)
    /// is the issuer; <paramref name="badgeIdentifier"/> must point
    /// at a Badge Definition this user controls.
    /// </summary>
    public async Task<BadgeAward> AwardBadgeAsync(
        string badgeIdentifier,
        IEnumerable<PublicKey> recipients,
        int powDifficulty = 0,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(badgeIdentifier);
        ArgumentNullException.ThrowIfNull(recipients);
        if (powDifficulty < 0) throw new ArgumentOutOfRangeException(nameof(powDifficulty));
        EnsureNotDisposed();
        var key = RequireKey(nameof(AwardBadgeAsync));

        var builder = BadgeAward.Create(BadgeDefinition.Address(key.PublicKey, badgeIdentifier));
        bool any = false;
        foreach (var r in recipients)
        {
            builder.ToRecipient(r);
            any = true;
        }

        if (!any)
        {
            throw new ArgumentException("At least one recipient is required.", nameof(recipients));
        }

        // NIP-58 PoW is optional. When the caller asks for it, the award
        // event id will sport `powDifficulty` leading zero bits.
        var ev = powDifficulty > 0
            ? builder.BuildMineAndSign(key, powDifficulty, cancellationToken)
            : builder.BuildAndSign(key);
        await _pool.PublishAsync(ev, cancellationToken).ConfigureAwait(false);
        return BadgeAward.FromEvent(ev);
    }

    /// <summary>
    /// Fetches the current Badge Definition for <paramref name="issuer"/>
    /// + <paramref name="identifier"/>. Returns <c>null</c> when none
    /// arrives before <paramref name="timeout"/>.
    /// </summary>
    public async Task<BadgeDefinition?> TryGetBadgeDefinitionAsync(
        PublicKey issuer,
        string identifier,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentException.ThrowIfNullOrEmpty(identifier);
        EnsureNotDisposed();

        var filter = new Filter
        {
            Kinds = new[] { Nip58Kinds.BadgeDefinition },
            Authors = new[] { issuer.ToHex() },
            TagFilters = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["d"] = new[] { identifier },
            },
            Limit = 1,
        };

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout ?? TimeSpan.FromSeconds(5));

        BadgeDefinition? best = null;
        try
        {
            await foreach (var received in SubscribeAsync(new[] { filter }, cts.Token).ConfigureAwait(false))
            {
                if (BadgeDefinition.TryFromEvent(received.Event, out var def)
                    && def is not null
                    && def.Identifier == identifier
                    && def.Issuer.Equals(issuer)
                    && (best is null || def.CreatedAt > best.CreatedAt))
                {
                    best = def;
                }
            }
        }
        catch (OperationCanceledException) { /* timeout */ }

        return best;
    }

    /// <summary>
    /// Fetches the current Profile Badges event for
    /// <paramref name="owner"/>, or <c>null</c> if none arrives in
    /// the timeout.
    /// </summary>
    public async Task<ProfileBadges?> TryGetProfileBadgesAsync(
        PublicKey owner,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(owner);
        EnsureNotDisposed();

        var filter = new Filter
        {
            Kinds = new[] { Nip58Kinds.ProfileBadges },
            Authors = new[] { owner.ToHex() },
            TagFilters = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["d"] = new[] { Nip58Kinds.ProfileBadgesIdentifier },
            },
            Limit = 1,
        };

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout ?? TimeSpan.FromSeconds(5));

        ProfileBadges? best = null;
        try
        {
            await foreach (var received in SubscribeAsync(new[] { filter }, cts.Token).ConfigureAwait(false))
            {
                if (ProfileBadges.TryFromEvent(received.Event, out var parsed)
                    && parsed is not null
                    && parsed.Owner.Equals(owner)
                    && (best is null || parsed.CreatedAt > best.CreatedAt))
                {
                    best = parsed;
                }
            }
        }
        catch (OperationCanceledException) { /* timeout */ }

        return best;
    }

    /// <summary>
    /// Adds <paramref name="award"/> to the calling user's profile
    /// badges (NIP-58 kind 30008). Fetches the existing Profile
    /// Badges event, appends the new (a, e) pair, and re-publishes.
    /// No-ops if the award is already on the profile.
    /// </summary>
    public async Task<ProfileBadges> AcceptBadgeAsync(
        BadgeAward award,
        string? recommendedRelay = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(award);
        EnsureNotDisposed();
        var key = RequireKey(nameof(AcceptBadgeAsync));

        var existing = await TryGetProfileBadgesAsync(key.PublicKey, cancellationToken: cancellationToken).ConfigureAwait(false);
        var builder = existing?.ToBuilder() ?? ProfileBadges.Create();

        // Idempotent — don't add a duplicate.
        bool already = existing?.Entries.Any(e =>
            e.AwardEventId.Equals(award.Id)) ?? false;
        if (!already)
        {
            builder.Add(award, recommendedRelay);
        }

        var ev = builder.BuildAndSign(key);
        await _pool.PublishAsync(ev, cancellationToken).ConfigureAwait(false);
        return ProfileBadges.FromEvent(ev);
    }

    /// <summary>
    /// Removes every entry referencing the given badge from the
    /// caller's Profile Badges event and re-publishes.
    /// </summary>
    public async Task<ProfileBadges?> RemoveBadgeFromProfileAsync(
        string badgeAddress,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(badgeAddress);
        EnsureNotDisposed();
        var key = RequireKey(nameof(RemoveBadgeFromProfileAsync));

        var existing = await TryGetProfileBadgesAsync(key.PublicKey, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (existing is null) return null;

        var builder = existing.ToBuilder().Remove(badgeAddress);
        var ev = builder.BuildAndSign(key);
        await _pool.PublishAsync(ev, cancellationToken).ConfigureAwait(false);
        return ProfileBadges.FromEvent(ev);
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
    /// <para>
    /// Without a configured event store: each relay delivery is yielded
    /// separately — the consumer decides whether to dedup. For a feed-style
    /// "each event once" experience, dedup on <c>received.Event.Id</c> in
    /// the loop.
    /// </para>
    /// <para>
    /// With a configured event store (<see cref="EventStore"/>): each
    /// arriving event flows through <c>StoreAsync</c> first. Events
    /// rejected as <see cref="StoreResult.Duplicate"/>,
    /// <see cref="StoreResult.Outdated"/>, <see cref="StoreResult.Deleted"/>,
    /// or <see cref="StoreResult.Expired"/> are not yielded — the
    /// consumer only sees new, replaced, or ephemeral events. For UI
    /// data binding, prefer <see cref="AttachAsync"/> +
    /// <see cref="INostrEventStore.ObserveAsync"/> over iterating this
    /// stream directly.
    /// </para>
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
                if (_eventStore is not null)
                {
                    StoreResult outcome;
                    try
                    {
                        outcome = await _eventStore.StoreAsync(received.Event, cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch
                    {
                        // Store failures must not poison the subscription stream.
                        outcome = StoreResult.Stored;
                    }

                    if (outcome is StoreResult.Duplicate
                        or StoreResult.Outdated
                        or StoreResult.Deleted
                        or StoreResult.Expired)
                    {
                        continue;
                    }
                }

                yield return new ReceivedEvent(received.Event, received.Relay);
            }
            else if (msg is SubscriptionClosed)
            {
                yield break;
            }
        }
    }

    /// <summary>
    /// Opens a subscription whose events flow into the attached
    /// <see cref="EventStore"/> rather than back to the caller. Read
    /// the resulting data via <see cref="INostrEventStore.QueryAsync"/>
    /// (snapshot) or <see cref="INostrEventStore.ObserveAsync"/> (live).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The returned <see cref="Task"/> completes when all relays close
    /// the subscription or <paramref name="cancellationToken"/> fires.
    /// Typical usage holds onto the cancellation token and lets the
    /// task run for the lifetime of the screen / feature:
    /// </para>
    /// <code>
    /// using var cts = new CancellationTokenSource();
    /// _ = client.AttachAsync(new[] { feedFilter }, cts.Token);
    ///
    /// // UI binds to the store:
    /// await foreach (var ev in store.ObserveAsync(uiFilter, cts.Token))
    ///     feedItems.Add(ev);
    /// </code>
    /// </remarks>
    /// <exception cref="InvalidOperationException">No event store is attached.</exception>
    /// <exception cref="ArgumentNullException">When <paramref name="filters"/> is null.</exception>
    public async Task AttachAsync(
        IReadOnlyList<Filter> filters,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filters);
        EnsureNotDisposed();
        if (_eventStore is null)
        {
            throw new InvalidOperationException(
                "AttachAsync requires an event store. Configure one via NostrClientBuilder.WithEventStore.");
        }

        string subscriptionId = "attach-" + Guid.NewGuid().ToString("N")[..16];
        await foreach (var msg in _pool.SubscribeAsync(subscriptionId, filters, cancellationToken).ConfigureAwait(false))
        {
            if (msg is SubscriptionEventReceived received)
            {
                try
                {
                    await _eventStore.StoreAsync(received.Event, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch
                {
                    // Store failures must not poison the subscription.
                }
            }
            else if (msg is SubscriptionClosed)
            {
                break;
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

    /// <summary>
    /// Yields per-relay connection state changes (Connecting / Connected /
    /// Disconnected) as they happen, including a snapshot of the current
    /// state of every relay in the pool on subscribe.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Use this to drive per-relay status indicators in UI, or to react to
    /// disconnects (e.g. re-issue subscriptions on reconnect — see below).
    /// Multi-consumer: two UI surfaces can call this independently without
    /// stealing events from each other.
    /// </para>
    /// <para>
    /// When <c>WithAutoReconnect</c> is on (default), the pool retries
    /// dropped connections with exponential backoff (1s → 30s cap) and
    /// emits <c>Connecting → Connected</c> on success or
    /// <c>Connecting → Disconnected(ConnectFailed)</c> per failed attempt.
    /// <see cref="RelayConnectionEvent.AttemptNumber"/> increments so UI
    /// can render "retrying… (attempt N)".
    /// </para>
    /// <para>
    /// In-flight <see cref="SubscribeAsync"/> / <see cref="AttachAsync"/>
    /// calls transparently re-issue their REQ across reconnects by default
    /// (see <c>NostrClientBuilder.WithAutoResubscribe</c>) — your
    /// <c>await foreach</c> keeps yielding events from the new connection
    /// without surfacing the transient drop.
    /// </para>
    /// <code>
    /// await foreach (var ev in client.ObserveRelayConnectionsAsync(ct))
    /// {
    ///     statusByRelay[ev.Relay] = ev.State;
    /// }
    /// </code>
    /// </remarks>
    public IAsyncEnumerable<RelayConnectionEvent> ObserveRelayConnectionsAsync(
        CancellationToken cancellationToken = default)
    {
        EnsureNotDisposed();
        return _pool.ObserveConnectionsAsync(cancellationToken);
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
    private bool _autoReconnect = true;
    private bool _autoResubscribe = true;
    private INostrEventStore? _eventStore;

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

    /// <summary>
    /// Enables (default) or disables automatic transport reconnect with
    /// exponential backoff (1s → 30s cap). State transitions are surfaced
    /// via <see cref="NostrClient.ObserveRelayConnectionsAsync"/> regardless
    /// of this setting; this only controls whether the pool retries after
    /// a disconnect or whether the app drives reconnect itself.
    /// </summary>
    public NostrClientBuilder WithAutoReconnect(bool enabled)
    {
        _autoReconnect = enabled;
        return this;
    }

    /// <summary>
    /// Enables (default) or disables transparent subscription resume across
    /// transport reconnects. When enabled, in-flight
    /// <see cref="NostrClient.SubscribeAsync"/> / <see cref="NostrClient.AttachAsync"/>
    /// calls re-issue their REQ on the relay after it reconnects, without
    /// surfacing a <see cref="SubscriptionClosed"/> for the transient drop.
    /// Has no effect when <see cref="WithAutoReconnect"/> is off.
    /// </summary>
    /// <remarks>
    /// Filters are re-issued as-supplied — if you use <c>Since</c> or
    /// <c>Limit</c>, expect overlap with events received before the drop.
    /// Pair with an event store for automatic dedup.
    /// </remarks>
    public NostrClientBuilder WithAutoResubscribe(bool enabled)
    {
        _autoResubscribe = enabled;
        return this;
    }

    /// <summary>
    /// Attaches an <see cref="INostrEventStore"/>. When set, the client
    /// auto-dedups on <see cref="NostrClient.SubscribeAsync"/> and enables
    /// <see cref="NostrClient.AttachAsync"/> for fire-and-forget
    /// subscriptions whose events flow into the store. UI code should
    /// read from <c>store.QueryAsync</c> / <c>store.ObserveAsync</c>
    /// instead of iterating the raw subscription stream.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="store"/> is null.</exception>
    public NostrClientBuilder WithEventStore(INostrEventStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        _eventStore = store;
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

        var pool = new RelayPool { AutoReconnect = _autoReconnect, AutoResubscribe = _autoResubscribe };
        try
        {
            await pool.ConnectAsync(_relays, cancellationToken).ConfigureAwait(false);
            return new NostrClient(_key, pool, ownsPool: true, _autoAuth, _eventStore);
        }
        catch
        {
            await pool.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}
