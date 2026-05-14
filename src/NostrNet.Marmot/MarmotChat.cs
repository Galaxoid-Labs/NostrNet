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

        var bundle = await provider.BuildKeyPackageAsync(
            myKey.PublicKey,
            ciphersuite,
            extensions: new ushort[] { MarmotMlsExtensions.MarmotGroupData },
            proposals: Array.Empty<ushort>(),
            ct).ConfigureAwait(false);

        var builder = KeyPackageEvent.Create(slot)
            .WithBundleBytes(bundle.BundleBytes)
            .WithCiphersuite(bundle.Ciphersuite)
            .WithExtension(MarmotMlsExtensions.MarmotGroupData);

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
