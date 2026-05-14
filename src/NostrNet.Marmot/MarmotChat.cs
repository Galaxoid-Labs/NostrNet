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
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Marmot.Events;
using NostrNet.Marmot.GroupData;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Marmot;

/// <summary>A live 1:1 Marmot conversation handle.</summary>
/// <param name="NostrGroupId">The 32-byte group id used in <c>h</c> tags on kind-445 events.</param>
/// <param name="Peer">The peer's Nostr x-only public key.</param>
public sealed record MarmotConversation(byte[] NostrGroupId, PublicKey Peer);

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
/// <param name="Plaintext">For <see cref="MarmotMessageKind.Application"/>, the decrypted plaintext (UTF-8). Null otherwise.</param>
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
public sealed record MarmotInboundMessage(
    MarmotMessageKind Kind,
    string? Plaintext,
    bool EpochAdvanced,
    PublicKey? Sender = null);

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
        string slot,
        IReadOnlyList<string> relays,
        ushort ciphersuite = DefaultCiphersuite,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(myKey);
        ArgumentException.ThrowIfNullOrEmpty(slot);
        ArgumentNullException.ThrowIfNull(relays);

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
            Conversation: new MarmotConversation(groupId, peerKp.Author),
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

            return new MarmotConversation(
                NostrGroupId: joined.NostrGroupId,
                Peer: welcome.Sender);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
        catch (System.IO.InvalidDataException)
        {
            return null;
        }
    }

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> as an application message in
    /// <paramref name="conversation"/> and returns a kind-445 GroupEvent
    /// ready to publish.
    /// </summary>
    public static async Task<NostrEvent> EncryptMessageAsync(
        IMarmotMlsProvider provider,
        MarmotConversation conversation,
        string plaintext,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(conversation);
        ArgumentNullException.ThrowIfNull(plaintext);

        byte[] mlsBytes = await provider.EncryptApplicationMessageAsync(
            conversation.NostrGroupId,
            SysEncoding.UTF8.GetBytes(plaintext),
            ct).ConfigureAwait(false);

        byte[] exporter = await provider.CurrentExporterSecretAsync(
            conversation.NostrGroupId, ct).ConfigureAwait(false);

        return GroupEvent.Build(mlsBytes, exporter, conversation.NostrGroupId);
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

            return SysEncoding.UTF8.GetString(processed.ApplicationPayload);
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

        string? plaintext = kind == MarmotMessageKind.Application
            ? SysEncoding.UTF8.GetString(processed.ApplicationPayload)
            : null;

        return new MarmotInboundMessage(kind, plaintext, processed.EpochAdvanced, processed.Sender);
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

        // Use the first peer as the conversation's "Peer" for the
        // MarmotConversation handle. The handle is only used for
        // exporter/group-id lookup; per-peer info lives elsewhere.
        return new MarmotGroupStarted(
            Conversation: new MarmotConversation(groupId, peerKps[0].Author),
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
