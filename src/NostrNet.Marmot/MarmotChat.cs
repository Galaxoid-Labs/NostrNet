// SPDX-License-Identifier: MIT
//
// MarmotChat — high-level 1:1 conversation helper.
//
// The Marmot envelope + IMarmotMlsProvider give you all the primitives
// you need to run an end-to-end encrypted conversation over Nostr, but
// stitching them together is fiddly. This module collapses the most
// common operations for a TWO-PARTY chat into four async methods:
//
//   BuildKeyPackageEventAsync   — generate + sign a kind-30443 KeyPackage
//                                  event you can publish to your inbox relays.
//   StartConversationAsync      — given a peer's KeyPackage event, create
//                                  a group, produce a kind-1059 gift-wrap
//                                  Welcome, and return both alongside a
//                                  MarmotConversation handle.
//   TryAcceptInviteAsync        — given a kind-1059 gift wrap addressed
//                                  to you, attempt to unwrap+join. Returns
//                                  a MarmotConversation handle on success.
//   EncryptMessageAsync         — within a conversation, encrypt a UTF-8
//                                  string into a kind-445 GroupEvent ready
//                                  to publish.
//   TryDecryptMessageAsync      — within a conversation, attempt to decrypt
//                                  a received kind-445 GroupEvent.
//
// All operations are async because IMarmotMlsProvider is async. The
// MarmotConversation handle is just (nostr_group_id, peer_pubkey) — the
// real state lives in the provider, keyed by group id.

using System.Diagnostics.CodeAnalysis;
using System.Text.Encodings.Web;
using System.Text.Json;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Marmot.Events;
using NostrNet.Marmot.GroupData;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Marmot;

/// <summary>
/// A live Marmot conversation handle. <strong>Every Marmot conversation
/// is structurally an MLS group with N members</strong> (N ≥ 2 for any
/// usable chat) — there's no separate "1:1" wire shape. The
/// <see cref="Peer"/> convenience is only set when the conversation was
/// created explicitly via <see cref="MarmotChat.StartConversationAsync"/>
/// (the dedicated 1:1 entry point); groups created via
/// <see cref="MarmotChat.StartGroupAsync"/>, including 2-member ones,
/// leave <see cref="Peer"/> null. Apps wanting to render "2-member
/// group looks like a 1:1" should derive the counterpart from
/// <see cref="Members"/>:
/// <code>
/// var counterpart = conv.Members.Count == 2
///     ? conv.Members.First(p =&gt; !p.Equals(mySelf))
///     : conv.Peer;
/// </code>
/// </summary>
/// <param name="NostrGroupId">The 32-byte group id used in <c>h</c> tags on kind-445 events.</param>
/// <param name="Peer">
/// Convenience for 1:1 conversations created via
/// <see cref="MarmotChat.StartConversationAsync"/> — the other party's
/// pubkey. <c>null</c> for groups (including 2-member groups created via
/// <see cref="MarmotChat.StartGroupAsync"/>), and for conversations
/// rehydrated from storage where N &gt; 2. Prefer <see cref="Members"/>
/// for interop-correct identification.
/// </param>
public sealed record MarmotConversation(byte[] NostrGroupId, PublicKey? Peer)
{
    /// <summary>
    /// Display name from the NostrGroupData extension (MIP-01). <c>null</c>
    /// when the underlying group has no extension or when the conversation
    /// was constructed without one. Empty string is permitted by the spec
    /// for "unnamed groups" — render empty the same as null.
    /// </summary>
    public string? Name { get; init; }

    /// <summary>
    /// Description from the NostrGroupData extension. <c>null</c> when not
    /// available.
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// All current members of the underlying MLS group, including this
    /// client's own identity. Populated at every construction site
    /// (StartConversationAsync, StartGroupAsync, AcceptInviteAsync,
    /// LoadExistingConversationsAsync) and refreshed on every
    /// <see cref="MarmotGroupStateChanged"/> after a Commit advances the
    /// epoch. For protocol-correct interop (e.g., distinguishing a
    /// 2-member group from a multi-member one regardless of which entry
    /// point the sender chose), prefer <c>Members.Count == 2</c> over
    /// <see cref="IsGroup"/>.
    /// </summary>
    public IReadOnlyList<PublicKey> Members { get; init; } = Array.Empty<PublicKey>();

    /// <summary>
    /// <c>true</c> when this is a multi-member group (or a 1:1 where the
    /// peer couldn't be derived). Equivalent to <c>Peer is null</c> but
    /// reads more cleanly in call sites. <strong>Note:</strong> a
    /// 2-member group created via <see cref="MarmotChat.StartGroupAsync"/>
    /// surfaces as <c>IsGroup == true</c> because the sender opted into
    /// the group entry point — apps that want "2-member groups look
    /// like 1:1" should use <see cref="Members"/> instead.
    /// </summary>
    public bool IsGroup => Peer is null;
}

/// <summary>The output of <see cref="MarmotChat.StartConversationAsync"/>.</summary>
/// <param name="Conversation">Handle to the freshly created conversation.</param>
/// <param name="WelcomeGiftWrap">
/// A kind-1059 gift-wrap event addressed to the peer. Publish this to the
/// peer's inbox relays; the peer's app should subscribe to kind-1059 with
/// a <c>p</c>-tag filter on their own pubkey and call
/// <see cref="MarmotChat.TryAcceptInviteAsync"/> on each one.
/// </param>
public sealed record MarmotConversationStarted(
    MarmotConversation Conversation,
    NostrEvent WelcomeGiftWrap);

/// <summary>The output of <see cref="MarmotChat.StartGroupAsync"/>.</summary>
/// <param name="Conversation">Handle to the freshly created group.</param>
/// <param name="WelcomeGiftWraps">One NIP-59 gift wrap per initial member. Publish each to that recipient's inbox relays.</param>
public sealed record MarmotGroupStarted(
    MarmotConversation Conversation,
    IReadOnlyList<NostrEvent> WelcomeGiftWraps);

/// <summary>The output of <see cref="MarmotChat.AddPeerAsync"/>.</summary>
/// <param name="WelcomeGiftWrap">NIP-59 gift wrap for the new peer.</param>
/// <param name="CommitGroupEvent">
/// kind-445 GroupEvent carrying the MLS Commit, encrypted with the
/// previous epoch's exporter so existing members can still decrypt it.
/// Publish to the group's relays.
/// </param>
public sealed record MarmotPeerAdded(
    NostrEvent WelcomeGiftWrap,
    NostrEvent CommitGroupEvent);

/// <summary>The output of <see cref="MarmotChat.RemovePeerAsync"/>.</summary>
/// <param name="CommitGroupEvent">
/// kind-445 GroupEvent carrying the Remove+Commit MLSMessage, encrypted
/// with the previous epoch's exporter so existing members (including
/// the to-be-removed one) can decrypt it. The removed member will
/// process the Commit, learn they were removed, and fail future
/// decrypts.
/// </param>
public sealed record MarmotPeerRemoved(NostrEvent CommitGroupEvent);

/// <summary>The output of <see cref="MarmotChat.RotateKeysAsync"/>.</summary>
/// <param name="CommitGroupEvent">
/// kind-445 GroupEvent carrying the self-update Commit, encrypted with
/// the previous epoch's exporter so existing members can process it.
/// </param>
public sealed record MarmotKeysRotated(NostrEvent CommitGroupEvent);

/// <summary>Classification of an inbound MLS message after decryption + processing.</summary>
public enum MarmotMessageKind
{
    /// <summary>Application data — <see cref="MarmotInboundMessage.Plaintext"/> is populated.</summary>
    Application,

    /// <summary>An MLS Commit — the group's epoch has advanced.</summary>
    Commit,

    /// <summary>An MLS Proposal — queued, not yet committed.</summary>
    Proposal,
}

/// <summary>The result of decrypting and processing one inbound kind-445.</summary>
/// <param name="Kind">What kind of MLS message was processed.</param>
/// <param name="Plaintext">For <see cref="MarmotMessageKind.Application"/>, the decrypted plaintext text body (UTF-8). Null otherwise.</param>
/// <param name="EpochAdvanced">
/// <c>true</c> if the group's epoch advanced as a result of processing
/// this message. Callers should treat any cached exporter secret as
/// stale; <see cref="MarmotChat.EncryptMessageAsync"/> always fetches
/// the live exporter so existing code keeps working.
/// </param>
/// <param name="Sender">
/// The Nostr pubkey of the member that produced this message, resolved
/// via the MLS layer (NOT trusting the outer kind-445's signature, which
/// uses an ephemeral key). <c>null</c> when the provider can't resolve
/// the sender (e.g. external proposals).
/// </param>
/// <param name="RumorId">
/// For <see cref="MarmotMessageKind.Application"/>, the inner Marmot rumor
/// id (canonical NIP-01 hash of the unsigned plaintext rumor). <c>null</c>
/// for non-application messages or when the plaintext payload isn't a
/// parseable rumor JSON (legacy / non-Marmot senders).
/// </param>
/// <param name="RumorKind">
/// For <see cref="MarmotMessageKind.Application"/>, the inner Nostr kind
/// (9 chat / 7 reaction / 5 deletion). <c>null</c> for non-application
/// messages. Defaults to <see cref="MarmotChat.ChatMessageRumorKind"/>
/// when the plaintext isn't a rumor JSON.
/// </param>
/// <param name="RumorTags">
/// For <see cref="MarmotMessageKind.Application"/>, the inner rumor's
/// tags. Empty when not applicable.
/// </param>
public sealed record MarmotInboundMessage(
    MarmotMessageKind Kind,
    string? Plaintext,
    bool EpochAdvanced,
    PublicKey? Sender = null,
    EventId? RumorId = null,
    int? RumorKind = null,
    IReadOnlyList<IReadOnlyList<string>>? RumorTags = null);

/// <summary>High-level helpers for one-to-one Marmot conversations.</summary>
public static class MarmotChat
{
    /// <summary>Default MLS ciphersuite identifier (X25519/HKDF-SHA256/AES-128-GCM/Ed25519).</summary>
    public const ushort DefaultCiphersuite = 0x0001;

    /// <summary>
    /// Generates a fresh MLS KeyPackage via <c>provider</c> and returns a
    /// signed kind-30443 <see cref="KeyPackageEvent"/> ready to publish.
    /// The <c>slot</c> becomes the event's <c>d</c>-tag, which makes this
    /// event parameterized-replaceable — republishing under the same slot
    /// replaces the prior KeyPackage.
    /// </summary>
    public static async Task<NostrEvent> BuildKeyPackageEventAsync(
        IMarmotMlsProvider provider,
        PrivateKey myKey,
        string? slot,
        IReadOnlyList<string> relays,
        ushort ciphersuite = DefaultCiphersuite,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(myKey);
        ArgumentNullException.ThrowIfNull(relays);

        // MIP-00 mandates the `d` tag be exactly 64 hex chars. Callers
        // that pass null/empty get a deterministic slot derived from
        // their identity pubkey — this is the "default device" slot,
        // and re-publishing under the same slot replaces the previous
        // KeyPackage on relays. Without slot stability, each run
        // creates a brand-new addressable event and old KeyPackages
        // (with init keys that have since been wiped from local state)
        // accumulate on the relay, causing inviters to encrypt
        // Welcomes against unreachable init keys → NoMatchingKeyPackage
        // when we try to join. Callers that want a separate slot
        // (e.g. per-device) supply their own 64-char hex.
        slot = NormalizeKeyPackageSlot(slot, myKey.PublicKey);

        // The Rust crate hardcodes the Marmot baseline capabilities
        // (LastResort + NostrGroupData extensions, SelfRemove proposal)
        // to match mdk-core exactly. The lists below are accepted for
        // forward compatibility but currently ignored by the provider;
        // the Nostr tags we attach below MUST match what the LeafNode
        // actually advertises or other clients will reject our KP.
        var bundle = await provider.BuildKeyPackageAsync(
            myKey.PublicKey,
            ciphersuite,
            extensions: new ushort[]
            {
                MarmotMlsExtensions.LastResort,
                MarmotMlsExtensions.MarmotGroupData,
            },
            proposals: new ushort[] { MarmotMlsProposalTypes.SelfRemove },
            ct).ConfigureAwait(false);

        var builder = KeyPackageEvent.Create(slot)
            .WithBundleBytes(bundle.BundleBytes)
            .WithCiphersuite(bundle.Ciphersuite)
            .WithExtension(MarmotMlsExtensions.LastResort)
            .WithExtension(MarmotMlsExtensions.MarmotGroupData)
            .WithProposal(MarmotMlsProposalTypes.SelfRemove);

        if (bundle.KeyPackageRef is not null)
        {
            builder.WithKeyPackageRef(bundle.KeyPackageRef);
        }

        if (relays.Count > 0)
        {
            builder.WithRelays(relays.ToArray());
        }

        return builder.Sign(myKey);
    }

    /// <summary>
    /// Starts a 1:1 conversation with the peer whose KeyPackage event is
    /// <c>peerKeyPackageEvent</c>. Creates a new MLS group, adds the
    /// peer, and gift-wraps the resulting Welcome for delivery.
    /// </summary>
    private static string NormalizeKeyPackageSlot(string? slot, PublicKey identityPubkey)
    {
        if (string.IsNullOrEmpty(slot))
        {
            // Deterministic default slot per identity. The hash domain
            // separator plus the pubkey produces a 32-byte slot id
            // that's the same across every run for this identity — so
            // re-publishing replaces the prior event under
            // (kind, pubkey, d) rather than creating yet another
            // orphan slot.
            ReadOnlySpan<byte> domain = "marmot/keypackage-default-slot/v1"u8;
            Span<byte> input = stackalloc byte[domain.Length + 32];
            domain.CopyTo(input);
            identityPubkey.CopyTo(input[domain.Length..]);
            Span<byte> hash = stackalloc byte[32];
            System.Security.Cryptography.SHA256.HashData(input, hash);
            return Convert.ToHexStringLower(hash);
        }

        if (slot.Length != 64 || !IsHex(slot))
        {
            throw new ArgumentException(
                $"KeyPackage slot (the d-tag value) must be a 64-character hex string per MIP-00; got '{slot}' ({slot.Length} chars).",
                nameof(slot));
        }

        return slot;

        static bool IsHex(string s)
        {
            foreach (char c in s)
            {
                if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F'))
                {
                    return false;
                }
            }

            return true;
        }
    }

    /// <summary>
    /// Starts a 1:1 Marmot conversation with the author of
    /// <paramref name="peerKeyPackageEvent"/>. Creates the MLS group,
    /// adds the peer using their KeyPackage, and builds the NIP-59
    /// gift-wrapped Welcome event the caller should publish.
    /// </summary>
    public static async Task<MarmotConversationStarted> StartConversationAsync(
        IMarmotMlsProvider provider,
        PrivateKey myKey,
        NostrEvent peerKeyPackageEvent,
        string? conversationName,
        IReadOnlyList<string> relays,
        ushort ciphersuite = DefaultCiphersuite,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(myKey);
        ArgumentNullException.ThrowIfNull(peerKeyPackageEvent);
        ArgumentNullException.ThrowIfNull(relays);

        var peerKp = KeyPackageEvent.FromEvent(peerKeyPackageEvent);

        byte[] groupId = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(groupId);

        var groupData = new MarmotGroupDataExtension
        {
            NostrGroupId = groupId,
            Name = conversationName ?? string.Empty,
            AdminPubkeys = new[] { myKey.PublicKey },
            Relays = relays,
        };

        await provider.CreateGroupAsync(myKey.PublicKey, groupData, ciphersuite, ct).ConfigureAwait(false);

        var add = await provider.AddMembersAsync(
            groupId,
            new ReadOnlyMemory<byte>[] { peerKp.KeyPackageBundleBytes },
            ct).ConfigureAwait(false);

        if (add.Welcomes.Count != 1)
        {
            throw new InvalidOperationException(
                $"Expected exactly one Welcome from a 1:1 Add; got {add.Welcomes.Count}.");
        }

        var giftWrap = WelcomeEvent.Build(
            mlsWelcomeBytes: add.Welcomes[0].WelcomeMlsMessageBytes,
            keyPackageEventId: peerKeyPackageEvent.Id.ToHex(),
            senderKey: myKey,
            recipientPubkey: peerKp.Author,
            recommendedRelays: relays);

        return new MarmotConversationStarted(
            Conversation: new MarmotConversation(groupId, peerKp.Author)
            {
                Name = groupData.Name,
                Description = groupData.Description,
                Members = new[] { myKey.PublicKey, peerKp.Author },
            },
            WelcomeGiftWrap: giftWrap);
    }

    /// <summary>
    /// Attempts to accept a Marmot conversation invitation carried by
    /// <c>giftWrap</c> (a kind-1059 gift-wrap event addressed to
    /// <c>myKey</c>). Returns the joined conversation on success, or
    /// <c>null</c> for any gift wrap that isn't a Marmot Welcome we can
    /// accept.
    /// </summary>
    public static async Task<MarmotConversation?> TryAcceptInviteAsync(
        IMarmotMlsProvider provider,
        PrivateKey myKey,
        NostrEvent giftWrap,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(myKey);
        ArgumentNullException.ThrowIfNull(giftWrap);

        if (!WelcomeEvent.TryUnwrap(giftWrap, myKey, out var welcome))
        {
            return null;
        }

        try
        {
            var joined = await provider.JoinGroupFromWelcomeAsync(
                welcome.MlsWelcomeBytes, ct).ConfigureAwait(false);

            // Pull the freshly-joined group's member list out of provider
            // storage so MarmotConversation.Members is populated. This is
            // one cheap FFI call per accept; without it apps can't tell a
            // 2-member group apart from a multi-member one when the
            // sender used StartGroupAsync (Whitenoise interop case).
            IReadOnlyList<PublicKey> members = Array.Empty<PublicKey>();
            try
            {
                var stored = await provider.ListGroupsAsync(ct).ConfigureAwait(false);
                var match = stored.FirstOrDefault(g =>
                    g.NostrGroupId.AsSpan().SequenceEqual(joined.NostrGroupId));
                if (match is not null)
                {
                    members = match.Members;
                }
            }
            catch
            {
                // ListGroupsAsync should not realistically fail right
                // after a successful join, but if it does, fall back to
                // an empty member list rather than failing the accept.
            }

            return new MarmotConversation(
                NostrGroupId: joined.NostrGroupId,
                Peer: welcome.Sender)
            {
                Name = joined.GroupData.Name,
                Description = joined.GroupData.Description,
                Members = members,
            };
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
        catch (System.IO.InvalidDataException)
        {
            return null;
        }
        catch (InvalidOperationException ex) when (IsStaleWelcomeFailure(ex.Message))
        {
            // Stale Welcomes are common in long-lived inboxes — a relay
            // serves the same kind-1059 days later, or we wiped our
            // local state since the inviter built it. Treat as a no-op.
            return null;
        }
        catch (InvalidOperationException ex) when (IsAlreadyJoinedFailure(ex.Message))
        {
            // We've already joined this group locally (e.g. the Welcome
            // is being redelivered by another relay). Surface the
            // existing conversation so the caller can resume it.
            var existing = await TryFindExistingConversationFromWelcomeAsync(
                provider, welcome, ct).ConfigureAwait(false);
            return existing;
        }
    }

    private static bool IsStaleWelcomeFailure(string message)
    {
        return message.Contains("NoMatchingKeyPackage", StringComparison.Ordinal)
            || message.Contains("WelcomeError", StringComparison.Ordinal);
    }

    private static bool IsAlreadyJoinedFailure(string message)
    {
        return message.Contains("GroupAlreadyExists", StringComparison.Ordinal);
    }

    /// <summary>
    /// When a Welcome arrives for a group we've already joined, scan
    /// the stored-groups list and rebuild the conversation handle so
    /// the caller still gets a usable object. We can't read the
    /// nostr_group_id out of the duplicate Welcome bytes without
    /// re-processing it (which would fail), so we match on the
    /// inviter being a current member of one of our groups.
    /// </summary>
    private static async Task<MarmotConversation?> TryFindExistingConversationFromWelcomeAsync(
        IMarmotMlsProvider provider,
        UnwrappedWelcome welcome,
        CancellationToken ct)
    {
        IReadOnlyList<MarmotStoredGroup> groups;
        try
        {
            groups = await provider.ListGroupsAsync(ct).ConfigureAwait(false);
        }
        catch
        {
            return null;
        }

        foreach (var g in groups)
        {
            foreach (var m in g.Members)
            {
                if (m.Equals(welcome.Sender))
                {
                    return new MarmotConversation(g.NostrGroupId, welcome.Sender)
                    {
                        Name = g.GroupData?.Name,
                        Description = g.GroupData?.Description,
                        Members = g.Members,
                    };
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Marmot chat-message rumor kind per MIP-03 / NIP-C7.
    /// </summary>
    public const int ChatMessageRumorKind = 9;

    /// <summary>
    /// NIP-25 reaction rumor kind. Reactions to Marmot messages travel
    /// inside the same kind-445 application channel — the inner rumor is
    /// a kind-7 carrying the reaction text (emoji / NIP-25 token) and an
    /// <c>e</c> tag referencing the target rumor id.
    /// </summary>
    public const int ReactionRumorKind = 7;

    /// <summary>
    /// NIP-09 deletion-request rumor kind. Deletions for Marmot messages
    /// travel inside the same kind-445 application channel — the inner
    /// rumor is a kind-5 carrying the optional reason as content plus
    /// <c>["e", targetRumorId]</c> and <c>["k", targetKind]</c> tags.
    /// </summary>
    public const int DeletionRumorKind = 5;

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> as an application message in
    /// <paramref name="conversation"/> and returns a kind-445 GroupEvent
    /// ready to publish.
    ///
    /// Per Marmot MIP-03 the plaintext fed into MLS is a JSON-serialized
    /// unsigned Nostr "rumor" event (kind <see cref="ChatMessageRumorKind"/>),
    /// authored by <paramref name="senderKey"/>. The rumor carries the
    /// real sender pubkey so that other Marmot clients (mdk-core / White
    /// Noise) can attribute the message; the MLS layer authenticates it.
    /// </summary>
    public static async Task<NostrEvent> EncryptMessageAsync(
        IMarmotMlsProvider provider,
        MarmotConversation conversation,
        PrivateKey senderKey,
        string plaintext,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(conversation);
        ArgumentNullException.ThrowIfNull(senderKey);
        ArgumentNullException.ThrowIfNull(plaintext);

        long createdAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        byte[] rumorJson = SerializeChatRumor(
            senderKey.PublicKey, createdAt, plaintext);

        byte[] mlsBytes = await provider.EncryptApplicationMessageAsync(
            conversation.NostrGroupId, rumorJson, ct).ConfigureAwait(false);

        byte[] exporter = await provider.CurrentExporterSecretAsync(
            conversation.NostrGroupId, ct).ConfigureAwait(false);

        return GroupEvent.Build(mlsBytes, exporter, conversation.NostrGroupId);
    }

    /// <summary>
    /// Builds an unsigned chat-message rumor (kind 9) optionally tagged
    /// with NIP-10 reply markers. Use this when you want to pre-compute
    /// the rumor id (via <see cref="UnsignedEvent.ComputeId"/>) before
    /// invoking <see cref="NostrMarmotClient.SendAsync"/> or
    /// <see cref="EncryptRumorAsync"/> — for example to write an
    /// optimistic UI row keyed on the rumor id before the encrypt +
    /// publish round-trip completes.
    /// </summary>
    /// <param name="text">The plaintext chat body.</param>
    /// <param name="author">The sender's identity pubkey (also the rumor's <c>pubkey</c>).</param>
    /// <param name="replyTo">
    /// Inner rumor id of the message being replied to. Emitted as a
    /// NIP-10 reply marker tag <c>["e", id, "", "reply"]</c>. Pass
    /// <c>null</c> when this isn't a reply.
    /// </param>
    /// <param name="replyRoot">
    /// Inner rumor id of the thread root. Emitted as a NIP-10 root
    /// marker tag <c>["e", id, "", "root"]</c>. Omit when the parent
    /// IS the root (NIP-10 says clients should distinguish the two but
    /// the root marker isn't strictly required for a depth-2 thread).
    /// </param>
    /// <param name="additionalTags">
    /// Extra tags appended AFTER the auto-built reply/root markers —
    /// caller-supplied mentions, NIP-40 expiration, etc. The marker
    /// positioning is preserved so NIP-10-aware consumers can find
    /// the markers at predictable offsets.
    /// </param>
    /// <param name="createdAt">Optional real timestamp; defaults to now.</param>
    public static UnsignedEvent BuildChatRumor(
        string text,
        PublicKey author,
        EventId? replyTo = null,
        EventId? replyRoot = null,
        IReadOnlyList<IReadOnlyList<string>>? additionalTags = null,
        DateTimeOffset? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(author);

        IReadOnlyList<IReadOnlyList<string>> tags;
        if (replyTo is null && replyRoot is null && (additionalTags is null || additionalTags.Count == 0))
        {
            tags = Array.Empty<IReadOnlyList<string>>();
        }
        else
        {
            var list = new List<IReadOnlyList<string>>();
            if (replyTo is not null)
            {
                list.Add(new[] { "e", replyTo.ToHex(), string.Empty, "reply" });
            }
            if (replyRoot is not null)
            {
                list.Add(new[] { "e", replyRoot.ToHex(), string.Empty, "root" });
            }
            if (additionalTags is not null)
            {
                foreach (var t in additionalTags)
                {
                    list.Add(t);
                }
            }
            tags = list;
        }

        return new UnsignedEvent
        {
            PubKey = author,
            CreatedAt = (createdAt ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds(),
            Kind = ChatMessageRumorKind,
            Tags = tags,
            Content = text,
        };
    }

    /// <summary>
    /// Builds an unsigned reaction rumor (kind 7) targeting
    /// <paramref name="targetRumorId"/>. Use this when you want to
    /// pre-compute the rumor id before invoking
    /// <see cref="NostrMarmotClient.SendReactionAsync"/> or
    /// <see cref="EncryptRumorAsync"/>.
    /// </summary>
    /// <param name="targetRumorId">The inner rumor id of the Marmot message being reacted to.</param>
    /// <param name="reaction">The reaction text — typically an emoji, <c>+</c>, <c>-</c>, or a NIP-25 <c>:shortcode:</c>.</param>
    /// <param name="author">The reactor's identity pubkey (also the rumor's <c>pubkey</c>).</param>
    /// <param name="additionalTags">Optional extra tags (e.g. NIP-25 custom-emoji declaration).</param>
    /// <param name="createdAt">Optional real timestamp; defaults to now.</param>
    public static UnsignedEvent BuildReactionRumor(
        EventId targetRumorId,
        string reaction,
        PublicKey author,
        IReadOnlyList<IReadOnlyList<string>>? additionalTags = null,
        DateTimeOffset? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(targetRumorId);
        ArgumentNullException.ThrowIfNull(reaction);
        ArgumentNullException.ThrowIfNull(author);

        var tags = new List<IReadOnlyList<string>>
        {
            new[] { "e", targetRumorId.ToHex() },
        };

        if (additionalTags is not null)
        {
            foreach (var t in additionalTags)
            {
                tags.Add(t);
            }
        }

        return new UnsignedEvent
        {
            PubKey = author,
            CreatedAt = (createdAt ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds(),
            Kind = ReactionRumorKind,
            Tags = tags,
            Content = reaction,
        };
    }

    /// <summary>
    /// Builds an unsigned NIP-09 deletion-request rumor (kind 5)
    /// targeting <paramref name="targetRumorId"/>. The rumor carries
    /// <c>["e", targetRumorId]</c> + <c>["k", targetKind]</c> tags.
    /// </summary>
    /// <param name="targetRumorId">The inner rumor id being deleted — NOT the outer kind-445 event id.</param>
    /// <param name="targetKind">The kind of the rumor being deleted (typically <see cref="ChatMessageRumorKind"/> or <see cref="ReactionRumorKind"/>).</param>
    /// <param name="author">The deleter's identity pubkey.</param>
    /// <param name="reason">Optional NIP-09 reason string; empty content when null.</param>
    /// <param name="createdAt">Optional real timestamp; defaults to now.</param>
    /// <remarks>
    /// NIP-09 validation (deletion's author must equal the targeted
    /// rumor's author) is the consumer's responsibility — the library
    /// can't enforce it because the original event isn't in scope.
    /// </remarks>
    public static UnsignedEvent BuildDeletionRumor(
        EventId targetRumorId,
        int targetKind,
        PublicKey author,
        string? reason = null,
        DateTimeOffset? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(targetRumorId);
        ArgumentNullException.ThrowIfNull(author);

        var tags = new List<IReadOnlyList<string>>
        {
            new[] { "e", targetRumorId.ToHex() },
            new[] { "k", targetKind.ToString(System.Globalization.CultureInfo.InvariantCulture) },
        };

        return new UnsignedEvent
        {
            PubKey = author,
            CreatedAt = (createdAt ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds(),
            Kind = DeletionRumorKind,
            Tags = tags,
            Content = reason ?? string.Empty,
        };
    }

    /// <summary>
    /// Encrypts an arbitrary unsigned Marmot rumor as an MLS application
    /// message and returns a kind-445 GroupEvent ready to publish. Use
    /// this when you need to send a non-chat rumor (reaction, deletion,
    /// or any other kind) and want explicit control over the rumor
    /// shape — for the common chat case prefer
    /// <see cref="EncryptMessageAsync"/>.
    /// </summary>
    public static async Task<NostrEvent> EncryptRumorAsync(
        IMarmotMlsProvider provider,
        MarmotConversation conversation,
        UnsignedEvent rumor,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(conversation);
        ArgumentNullException.ThrowIfNull(rumor);

        byte[] rumorJson = SerializeRumor(rumor);

        byte[] mlsBytes = await provider.EncryptApplicationMessageAsync(
            conversation.NostrGroupId, rumorJson, ct).ConfigureAwait(false);

        byte[] exporter = await provider.CurrentExporterSecretAsync(
            conversation.NostrGroupId, ct).ConfigureAwait(false);

        return GroupEvent.Build(mlsBytes, exporter, conversation.NostrGroupId);
    }

    /// <summary>
    /// Build the JSON wire form of a Marmot chat-message rumor (an
    /// unsigned Nostr event with id but no sig). Exposed internally so
    /// the tests + receive path can produce / verify identical bytes.
    /// </summary>
    internal static byte[] SerializeChatRumor(
        PublicKey senderPubkey,
        long createdAt,
        string content)
    {
        var rumor = new UnsignedEvent
        {
            PubKey = senderPubkey,
            CreatedAt = createdAt,
            Kind = ChatMessageRumorKind,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = content,
        };
        return SerializeRumor(rumor);
    }

    /// <summary>
    /// Build the JSON wire form of any Marmot rumor (unsigned Nostr event
    /// with canonical id + no sig). Shared between chat / reaction /
    /// deletion encrypt paths so all kinds round-trip through identical
    /// bytes.
    /// </summary>
    internal static byte[] SerializeRumor(UnsignedEvent rumor)
    {
        EventId id = rumor.ComputeId();

        using var ms = new MemoryStream();
        var options = new JsonWriterOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };
        using (var writer = new Utf8JsonWriter(ms, options))
        {
            writer.WriteStartObject();
            writer.WriteString("id", id.ToHex());
            writer.WriteString("pubkey", rumor.PubKey.ToHex());
            writer.WriteNumber("created_at", rumor.CreatedAt);
            writer.WriteNumber("kind", rumor.Kind);
            writer.WriteStartArray("tags");
            foreach (var row in rumor.Tags)
            {
                writer.WriteStartArray();
                foreach (var cell in row)
                {
                    writer.WriteStringValue(cell);
                }
                writer.WriteEndArray();
            }
            writer.WriteEndArray();
            writer.WriteString("content", rumor.Content);
            writer.WriteEndObject();
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Parsed shape of a Marmot rumor payload. <see cref="Id"/> is the
    /// rumor's NIP-01 canonical id; <see cref="Sender"/> is the rumor's
    /// declared author (unsigned — for cryptographic identification use
    /// the MLS-resolved sender from the provider instead).
    /// </summary>
    internal sealed record ParsedRumor(
        EventId? Id,
        int Kind,
        IReadOnlyList<IReadOnlyList<string>> Tags,
        string Content,
        PublicKey? Sender);

    /// <summary>
    /// Parses a decrypted Marmot application-message plaintext. Per MIP-03
    /// the plaintext is the JSON of an unsigned Nostr event; this lifts
    /// the rumor's id, kind, tags, content, and declared author. Returns
    /// <c>null</c> when the bytes don't parse as a rumor — apps fall back
    /// to rendering the raw UTF-8 with sensible defaults.
    /// </summary>
    internal static ParsedRumor? TryParseRumor(byte[] plaintextBytes)
    {
        ArgumentNullException.ThrowIfNull(plaintextBytes);
        if (plaintextBytes.Length == 0 || plaintextBytes[0] != (byte)'{')
        {
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(plaintextBytes);
            var root = doc.RootElement;

            EventId? id = null;
            if (root.TryGetProperty("id", out var idEl) && idEl.ValueKind == JsonValueKind.String
                && idEl.GetString() is string idHex && idHex.Length == 64)
            {
                try { id = EventId.FromHex(idHex); }
                catch { id = null; }
            }

            int kind = ChatMessageRumorKind;
            if (root.TryGetProperty("kind", out var kindEl) && kindEl.ValueKind == JsonValueKind.Number
                && kindEl.TryGetInt32(out int k))
            {
                kind = k;
            }

            var tags = new List<IReadOnlyList<string>>();
            if (root.TryGetProperty("tags", out var tagsEl) && tagsEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var row in tagsEl.EnumerateArray())
                {
                    if (row.ValueKind != JsonValueKind.Array) continue;
                    var rowList = new List<string>();
                    foreach (var cell in row.EnumerateArray())
                    {
                        rowList.Add(cell.ValueKind == JsonValueKind.String
                            ? cell.GetString() ?? string.Empty
                            : cell.ToString());
                    }
                    tags.Add(rowList);
                }
            }

            string content = root.TryGetProperty("content", out var c) && c.ValueKind == JsonValueKind.String
                ? c.GetString() ?? string.Empty
                : string.Empty;

            PublicKey? sender = null;
            if (root.TryGetProperty("pubkey", out var p) && p.ValueKind == JsonValueKind.String
                && p.GetString() is string hex && hex.Length == 64)
            {
                try { sender = PublicKey.FromHex(hex); }
                catch { sender = null; }
            }

            return new ParsedRumor(
                Id: id,
                Kind: kind,
                Tags: tags,
                Content: content,
                Sender: sender);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Extracts the human-readable text from a decrypted Marmot
    /// application-message plaintext. Per MIP-03 the plaintext is the
    /// JSON of an unsigned Nostr event; the chat content is the
    /// <c>content</c> field. Returns the input unchanged when the
    /// plaintext doesn't look like a rumor JSON, so legacy / non-Marmot
    /// senders still surface something readable.
    /// </summary>
    internal static (string Content, PublicKey? Sender) ExtractChatRumor(byte[] plaintextBytes)
    {
        var parsed = TryParseRumor(plaintextBytes);
        return parsed is null
            ? (SysEncoding.UTF8.GetString(plaintextBytes), null)
            : (parsed.Content, parsed.Sender);
    }

    /// <summary>
    /// Attempts to decrypt a kind-445 GroupEvent in the given conversation.
    /// Returns the plaintext on success or <c>null</c> for any decrypt /
    /// parse / replay failure (so it's safe to call against arbitrary
    /// kind-445 events filtered by <c>h</c>-tag).
    /// </summary>
    public static async Task<string?> TryDecryptMessageAsync(
        IMarmotMlsProvider provider,
        MarmotConversation conversation,
        NostrEvent groupEvent,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(conversation);
        ArgumentNullException.ThrowIfNull(groupEvent);

        if (groupEvent.Kind != MarmotKinds.GroupEvent)
        {
            return null;
        }

        byte[] exporter;
        try
        {
            exporter = await provider.CurrentExporterSecretAsync(
                conversation.NostrGroupId, ct).ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
            return null;
        }

        if (!GroupEvent.TryDecrypt(groupEvent, exporter, out var decrypted))
        {
            return null;
        }

        try
        {
            var processed = await provider.ProcessIncomingMlsMessageAsync(
                conversation.NostrGroupId,
                decrypted.MlsMessageBytes,
                ct).ConfigureAwait(false);

            // Per MIP-03 the MLS payload is a JSON rumor; extract the
            // human-readable text from its `content` field. Returns the
            // raw UTF-8 bytes when the payload is not a rumor.
            return ExtractChatRumor(processed.ApplicationPayload).Content;
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException
                                     or System.IO.InvalidDataException
                                     or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// Convenience overload of <see cref="TryDecryptMessageAsync"/> that
    /// returns the result via an out parameter (handy in non-async
    /// pattern-matching code paths).
    /// </summary>
    public static async Task<(bool Ok, string? Plaintext)> TryDecryptMessageWithStatusAsync(
        IMarmotMlsProvider provider,
        MarmotConversation conversation,
        NostrEvent groupEvent,
        CancellationToken ct = default)
    {
        string? text = await TryDecryptMessageAsync(provider, conversation, groupEvent, ct).ConfigureAwait(false);
        return (text is not null, text);
    }

    /// <summary>
    /// Like <see cref="TryDecryptMessageAsync"/>, but exposes the MLS
    /// message classification — so callers can react to inbound Commits
    /// (group state changes) as well as application messages. Returns
    /// <c>null</c> on any decrypt / parse failure.
    /// </summary>
    public static async Task<MarmotInboundMessage?> TryProcessMessageAsync(
        IMarmotMlsProvider provider,
        MarmotConversation conversation,
        NostrEvent groupEvent,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(conversation);
        ArgumentNullException.ThrowIfNull(groupEvent);

        if (groupEvent.Kind != MarmotKinds.GroupEvent)
        {
            return null;
        }

        byte[] exporter;
        try
        {
            exporter = await provider.CurrentExporterSecretAsync(
                conversation.NostrGroupId, ct).ConfigureAwait(false);
        }
        catch (InvalidOperationException)
        {
            return null;
        }

        if (!GroupEvent.TryDecrypt(groupEvent, exporter, out var decrypted))
        {
            return null;
        }

        ProcessedMlsMessage processed;
        try
        {
            processed = await provider.ProcessIncomingMlsMessageAsync(
                conversation.NostrGroupId,
                decrypted.MlsMessageBytes,
                ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException
                                     or System.IO.InvalidDataException
                                     or InvalidOperationException)
        {
            return null;
        }

        var kind = processed.Kind switch
        {
            MlsMessageKind.Application => MarmotMessageKind.Application,
            MlsMessageKind.Commit => MarmotMessageKind.Commit,
            MlsMessageKind.Proposal => MarmotMessageKind.Proposal,
            _ => MarmotMessageKind.Application,
        };

        string? plaintext = null;
        PublicKey? sender = processed.Sender;
        EventId? rumorId = null;
        int? rumorKind = null;
        IReadOnlyList<IReadOnlyList<string>>? rumorTags = null;
        if (kind == MarmotMessageKind.Application)
        {
            var parsed = TryParseRumor(processed.ApplicationPayload);
            if (parsed is not null)
            {
                plaintext = parsed.Content;
                // Prefer the MLS-resolved sender when available; the rumor
                // pubkey is unsigned and could be spoofed, but a Marmot-
                // conforming peer always sets it to the same identity the
                // MLS layer authenticates, so it's useful as a fallback.
                sender ??= parsed.Sender;
                rumorId = parsed.Id;
                rumorKind = parsed.Kind;
                rumorTags = parsed.Tags;
            }
            else
            {
                plaintext = SysEncoding.UTF8.GetString(processed.ApplicationPayload);
            }
        }

        return new MarmotInboundMessage(
            kind, plaintext, processed.EpochAdvanced, sender,
            rumorId, rumorKind, rumorTags);
    }

    /// <summary>
    /// Founder bootstrap for a group with multiple initial members. Creates
    /// the MLS group, adds all peers in one Commit, and produces one
    /// NIP-59 gift wrap per peer. There is no separate Commit broadcast
    /// because at creation time there are no existing members to inform.
    /// </summary>
    public static async Task<MarmotGroupStarted> StartGroupAsync(
        IMarmotMlsProvider provider,
        PrivateKey myKey,
        IReadOnlyList<NostrEvent> peerKeyPackageEvents,
        string? conversationName,
        IReadOnlyList<string> relays,
        ushort ciphersuite = DefaultCiphersuite,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(myKey);
        ArgumentNullException.ThrowIfNull(peerKeyPackageEvents);
        ArgumentNullException.ThrowIfNull(relays);

        if (peerKeyPackageEvents.Count == 0)
        {
            throw new ArgumentException("group must have at least one initial peer", nameof(peerKeyPackageEvents));
        }

        var peerKps = new KeyPackageEvent[peerKeyPackageEvents.Count];
        var bundles = new ReadOnlyMemory<byte>[peerKeyPackageEvents.Count];
        for (int i = 0; i < peerKeyPackageEvents.Count; i++)
        {
            peerKps[i] = KeyPackageEvent.FromEvent(peerKeyPackageEvents[i]);
            bundles[i] = peerKps[i].KeyPackageBundleBytes;
        }

        byte[] groupId = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(groupId);

        var groupData = new MarmotGroupDataExtension
        {
            NostrGroupId = groupId,
            Name = conversationName ?? string.Empty,
            AdminPubkeys = new[] { myKey.PublicKey },
            Relays = relays,
        };

        await provider.CreateGroupAsync(myKey.PublicKey, groupData, ciphersuite, ct).ConfigureAwait(false);

        var add = await provider.AddMembersAsync(groupId, bundles, ct).ConfigureAwait(false);

        if (add.Welcomes.Count != peerKps.Length)
        {
            throw new InvalidOperationException(
                $"expected {peerKps.Length} welcome entries; got {add.Welcomes.Count}.");
        }

        var giftWraps = new NostrEvent[peerKps.Length];
        for (int i = 0; i < peerKps.Length; i++)
        {
            giftWraps[i] = WelcomeEvent.Build(
                mlsWelcomeBytes: add.Welcomes[i].WelcomeMlsMessageBytes,
                keyPackageEventId: peerKeyPackageEvents[i].Id.ToHex(),
                senderKey: myKey,
                recipientPubkey: peerKps[i].Author,
                recommendedRelays: relays);
        }

        // Peer is null for multi-member groups so it agrees with what
        // LoadExistingConversationsAsync sees on the next session.
        // For a 1:1-shaped use of StartGroupAsync (single peer in the
        // list, which is functionally identical to StartConversationAsync)
        // we keep the peer set so app code can render the 1:1 peer chip.
        PublicKey? handlePeer = peerKps.Length == 1 ? peerKps[0].Author : null;

        var members = new PublicKey[peerKps.Length + 1];
        members[0] = myKey.PublicKey;
        for (int i = 0; i < peerKps.Length; i++)
        {
            members[i + 1] = peerKps[i].Author;
        }

        return new MarmotGroupStarted(
            Conversation: new MarmotConversation(groupId, handlePeer)
            {
                Name = groupData.Name,
                Description = groupData.Description,
                Members = members,
            },
            WelcomeGiftWraps: giftWraps);
    }

    /// <summary>
    /// Adds a new peer to an existing conversation. Captures the current
    /// epoch's exporter BEFORE issuing the Add (so existing members can
    /// still decrypt the Commit GroupEvent), then advances the group.
    /// </summary>
    /// <returns>
    /// A NIP-59 Welcome gift wrap for the new peer AND a kind-445
    /// GroupEvent carrying the Commit MLSMessage encrypted with the
    /// previous epoch's exporter. Both should be published.
    /// </returns>
    public static async Task<MarmotPeerAdded> AddPeerAsync(
        IMarmotMlsProvider provider,
        PrivateKey myKey,
        MarmotConversation conversation,
        NostrEvent peerKeyPackageEvent,
        IReadOnlyList<string> relays,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(myKey);
        ArgumentNullException.ThrowIfNull(conversation);
        ArgumentNullException.ThrowIfNull(peerKeyPackageEvent);
        ArgumentNullException.ThrowIfNull(relays);

        var peerKp = KeyPackageEvent.FromEvent(peerKeyPackageEvent);

        // Capture the CURRENT epoch's exporter so existing members can
        // still decrypt the Commit GroupEvent we're about to broadcast.
        byte[] oldExporter = await provider
            .CurrentExporterSecretAsync(conversation.NostrGroupId, ct)
            .ConfigureAwait(false);

        var add = await provider.AddMembersAsync(
            conversation.NostrGroupId,
            new ReadOnlyMemory<byte>[] { peerKp.KeyPackageBundleBytes },
            ct).ConfigureAwait(false);

        if (add.Welcomes.Count != 1)
        {
            throw new InvalidOperationException(
                $"expected exactly one welcome from a single-peer Add; got {add.Welcomes.Count}.");
        }

        var welcomeGiftWrap = WelcomeEvent.Build(
            mlsWelcomeBytes: add.Welcomes[0].WelcomeMlsMessageBytes,
            keyPackageEventId: peerKeyPackageEvent.Id.ToHex(),
            senderKey: myKey,
            recipientPubkey: peerKp.Author,
            recommendedRelays: relays);

        // The Commit GroupEvent is encrypted with the OLD exporter so
        // existing members (still at the previous epoch) can decrypt it.
        var commitGroupEvent = GroupEvent.Build(
            mlsMessageBytes: add.CommitMlsMessageBytes,
            exporterSecret: oldExporter,
            nostrGroupId: conversation.NostrGroupId);

        return new MarmotPeerAdded(welcomeGiftWrap, commitGroupEvent);
    }

    /// <summary>
    /// Removes one or more peers from an existing conversation. The
    /// returned Commit GroupEvent is encrypted with the previous epoch's
    /// exporter so that existing members AND the about-to-be-removed
    /// peers can decrypt it; the latter then learn (via processing the
    /// Commit) that they were removed and fail subsequent decrypts.
    /// </summary>
    public static async Task<MarmotPeerRemoved> RemovePeerAsync(
        IMarmotMlsProvider provider,
        MarmotConversation conversation,
        IReadOnlyList<PublicKey> peersToRemove,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(conversation);
        ArgumentNullException.ThrowIfNull(peersToRemove);

        if (peersToRemove.Count == 0)
        {
            throw new ArgumentException("must remove at least one peer", nameof(peersToRemove));
        }

        byte[] oldExporter = await provider
            .CurrentExporterSecretAsync(conversation.NostrGroupId, ct)
            .ConfigureAwait(false);

        var result = await provider.RemoveMembersAsync(
            conversation.NostrGroupId, peersToRemove, ct).ConfigureAwait(false);

        var commitGroupEvent = GroupEvent.Build(
            mlsMessageBytes: result.CommitMlsMessageBytes,
            exporterSecret: oldExporter,
            nostrGroupId: conversation.NostrGroupId);

        return new MarmotPeerRemoved(commitGroupEvent);
    }

    /// <summary>
    /// Rotates the local member's leaf keys via MLS self-update. The
    /// returned Commit GroupEvent is encrypted with the previous epoch's
    /// exporter so all existing members can process it.
    /// </summary>
    public static async Task<MarmotKeysRotated> RotateKeysAsync(
        IMarmotMlsProvider provider,
        MarmotConversation conversation,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(conversation);

        byte[] oldExporter = await provider
            .CurrentExporterSecretAsync(conversation.NostrGroupId, ct)
            .ConfigureAwait(false);

        var result = await provider.SelfUpdateAsync(conversation.NostrGroupId, ct).ConfigureAwait(false);

        var commitGroupEvent = GroupEvent.Build(
            mlsMessageBytes: result.CommitMlsMessageBytes,
            exporterSecret: oldExporter,
            nostrGroupId: conversation.NostrGroupId);

        return new MarmotKeysRotated(commitGroupEvent);
    }

    /// <summary>
    /// Filter helper: returns <c>true</c> if <paramref name="ev"/> looks
    /// like a kind-445 group event targeting
    /// <paramref name="conversation"/>'s <c>nostr_group_id</c> (matches
    /// the <c>h</c> tag). Does NOT attempt decryption.
    /// </summary>
    [SuppressMessage("Performance", "CA1865", Justification = "Strings interpolation kept readable.")]
    public static bool LooksLikeGroupEventFor(MarmotConversation conversation, NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        ArgumentNullException.ThrowIfNull(ev);

        if (ev.Kind != MarmotKinds.GroupEvent)
        {
            return false;
        }

        string expected = Convert.ToHexStringLower(conversation.NostrGroupId);
        return string.Equals(ev.Tags.FirstValue("h"), expected, StringComparison.Ordinal);
    }
}
