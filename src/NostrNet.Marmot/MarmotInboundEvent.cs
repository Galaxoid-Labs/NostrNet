// SPDX-License-Identifier: MIT
//
// Typed inbound events surfaced by NostrMarmotClient.SubscribeAsync.
// Three categories: invites (someone wants to start a conversation),
// messages (decrypted application data), and group-state changes
// (Commits — adds, removes, key rotations).

using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Marmot;

/// <summary>Base type for events surfaced by <see cref="NostrMarmotClient.SubscribeAsync"/>.</summary>
public abstract record MarmotInboundEvent;

/// <summary>
/// A NIP-59 gift wrap addressed to this client successfully unwrapped
/// as a Marmot Welcome. The conversation has NOT yet been joined —
/// call <see cref="NostrMarmotClient.AcceptInviteAsync"/> to actually
/// process the Welcome and start receiving group events.
/// </summary>
/// <param name="Sender">The Nostr pubkey of the inviter (verified via the seal signature).</param>
/// <param name="KeyPackageEventId">The kind-30443 event id the inviter used to add you.</param>
/// <param name="RecommendedRelays">Relays the inviter suggests for the conversation.</param>
/// <param name="OriginalGiftWrap">The raw kind-1059 event — kept for accept-time replay.</param>
public sealed record MarmotInviteReceived(
    PublicKey Sender,
    string KeyPackageEventId,
    IReadOnlyList<string> RecommendedRelays,
    NostrEvent OriginalGiftWrap) : MarmotInboundEvent;

/// <summary>
/// A kind-445 GroupEvent in <see cref="Conversation"/> decrypted as an
/// MLS application message.
/// </summary>
/// <param name="Conversation">The conversation this message belongs to.</param>
/// <param name="EventId">
/// The outer kind-445 event id. Use this as the dedup key when the same
/// message arrives from multiple relays or when persisting to an
/// <see cref="IMarmotMessageLog"/>.
/// </param>
/// <param name="Sender">
/// <strong>May be null</strong> when the MLS layer can't resolve the leaf
/// to a Nostr pubkey. When non-null, this is the cryptographically
/// verified sender resolved via the MLS layer (NOT the ephemeral outer
/// signature on the kind-445 event), so it cannot be spoofed by a
/// malicious outer wrap. Apps should null-check before using; treating
/// null as "unknown sender" is the safe rendering.
/// </param>
/// <param name="Plaintext">The decrypted UTF-8 plaintext.</param>
/// <param name="ServerTimestamp">The kind-445 event's <c>created_at</c>.</param>
public sealed record MarmotMessageReceived(
    MarmotConversation Conversation,
    EventId EventId,
    PublicKey? Sender,
    string Plaintext,
    DateTimeOffset ServerTimestamp) : MarmotInboundEvent;

/// <summary>
/// A kind-445 GroupEvent in <see cref="Conversation"/> decrypted as an
/// MLS Commit (group state change — add, remove, key rotation).
/// The client's local provider state has already been advanced.
/// </summary>
/// <param name="Conversation">The conversation whose state changed.</param>
/// <param name="Sender">The Nostr pubkey of the member who issued the Commit. Null when unresolvable.</param>
public sealed record MarmotGroupStateChanged(
    MarmotConversation Conversation,
    PublicKey? Sender) : MarmotInboundEvent;
