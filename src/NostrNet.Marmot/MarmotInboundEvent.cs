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
/// <param name="Sender">
/// The Nostr pubkey on the NIP-59 <em>seal</em> (kind-13) — library-
/// verified (the seal's signature over the inner rumor checked out and
/// the outer gift-wrap can't have spoofed it). <strong>This is not
/// guaranteed to be the inviter's identity pubkey.</strong> NIP-59
/// says the seal SHOULD be signed by the sender's identity key, but
/// interop with clients that seal welcomes using non-identity / ephemeral
/// keys (e.g., some Whitenoise builds) means a single inviter can
/// surface as multiple distinct <c>Sender</c> values across welcomes for
/// the same eventual MLS group. After accept, use
/// <see cref="MarmotConversation.Members"/> to identify the counterpart
/// — that's the MLS-bound identity. Don't feed <c>Sender</c> into
/// kind-0 author filters or other identity-keyed UX; reserve those for
/// post-accept members.
/// </param>
/// <param name="KeyPackageEventId">The kind-30443 event id the inviter used to add you.</param>
/// <param name="RecommendedRelays">Relays the inviter suggests for the conversation.</param>
/// <param name="OriginalGiftWrap">The raw kind-1059 event — kept for accept-time replay.</param>
/// <remarks>
/// The inbox pump filters welcomes whose target KeyPackage has been
/// rotated away or wiped from the local provider (a stale welcome
/// where <see cref="NostrMarmotClient.AcceptInviteAsync"/> would just
/// return null). Apps therefore only see invites the receiver could
/// actually accept against current local state.
/// </remarks>
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
/// <param name="RumorId">
/// The <strong>inner Marmot rumor id</strong> — derived from the canonical
/// NIP-01 hash of the unsigned JSON payload that was MLS-encrypted. This
/// is the stable, sender-agnostic identifier for the logical message
/// and is what reactions / deletions should reference via their
/// <c>e</c> tag (NOT the outer <see cref="EventId"/>, which would vary
/// across senders republishing the same content).
/// </param>
/// <param name="RumorKind">
/// The inner Nostr kind: <c>9</c> for chat messages
/// (<see cref="MarmotChat.ChatMessageRumorKind"/>), <c>7</c> for reactions
/// (<see cref="MarmotChat.ReactionRumorKind"/>), <c>5</c> for NIP-09
/// deletion requests (<see cref="MarmotChat.DeletionRumorKind"/>). Apps
/// switch on this to route chat vs. reaction vs. deletion.
/// </param>
/// <param name="RumorTags">
/// The inner rumor's tags. For reactions: <c>["e", targetRumorId]</c>
/// and optionally <c>["p", targetAuthor]</c>. For deletions:
/// <c>["e", targetRumorId]</c> and <c>["k", targetKind]</c>. For chat
/// messages: typically empty.
/// </param>
/// <param name="Sender">
/// <strong>May be null</strong> when the MLS layer can't resolve the leaf
/// to a Nostr pubkey. When non-null, this is the cryptographically
/// verified sender resolved via the MLS layer (NOT the ephemeral outer
/// signature on the kind-445 event), so it cannot be spoofed by a
/// malicious outer wrap. Apps should null-check before using; treating
/// null as "unknown sender" is the safe rendering.
/// </param>
/// <param name="Plaintext">
/// The decrypted text body. For chat messages this is the human-readable
/// content; for reactions it's the emoji / NIP-25 token; for deletion
/// requests it's the optional reason string (empty when none was given).
/// </param>
/// <param name="ServerTimestamp">The kind-445 event's <c>created_at</c>.</param>
/// <remarks>
/// <para>
/// NIP-09 deletion validation is the consumer's responsibility — apps
/// only honor a kind-5 rumor when <see cref="Sender"/> matches the
/// author of the targeted rumor (looked up in the local message log /
/// store). The library can't enforce this since the original event
/// isn't in scope.
/// </para>
/// </remarks>
public sealed record MarmotMessageReceived(
    MarmotConversation Conversation,
    EventId EventId,
    EventId RumorId,
    int RumorKind,
    IReadOnlyList<IReadOnlyList<string>> RumorTags,
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
