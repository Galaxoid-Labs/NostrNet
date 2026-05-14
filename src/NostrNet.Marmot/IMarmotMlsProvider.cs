// SPDX-License-Identifier: MIT
//
// Contract between NostrNet.Marmot (the Nostr-wire/envelope layer) and a
// pluggable MLS engine implementation. NostrNet.Marmot does NOT include
// an MLS engine. To actually run Marmot you need a provider that wraps
// an MLS library (e.g. openmls via P/Invoke, MLS.NET, etc.).
//
// All MLS-domain blobs (KeyPackage bytes, MLSMessage bytes, Welcome
// bytes, exporter secrets) cross this interface as `ReadOnlyMemory<byte>`
// or `byte[]`. The 32-byte Nostr group id is used as the handle for
// existing group state — the provider stores/retrieves the underlying
// MLS group state by that id internally.

using NostrNet.Keys;
using NostrNet.Marmot.GroupData;

namespace NostrNet.Marmot;

/// <summary>
/// Implemented by a Marmot-aware MLS engine. NostrNet.Marmot calls into
/// this interface for every operation that touches MLS internals.
/// </summary>
/// <remarks>
/// <para>All methods are async to leave room for FFI hops and disk-backed
/// state; trivial in-memory implementations can return completed tasks.</para>
/// <para>Implementations are expected to:</para>
/// <list type="bullet">
///   <item><description>Persist MLS group state keyed by 32-byte
///   <c>nostr_group_id</c> (the value carried in the Marmot Group Data
///   extension, also surfaced in the <c>h</c>-tag of kind-445 events).</description></item>
///   <item><description>Validate signatures, ratchet state, and epoch
///   transitions per RFC 9420.</description></item>
///   <item><description>Surface the per-epoch MLS exporter secret derived
///   with <c>label = "marmot"</c> and <c>context = "group-event"</c>, used
///   by <see cref="Events.GroupEvent.Build"/>.</description></item>
/// </list>
/// </remarks>
public interface IMarmotMlsProvider
{
    // ────────────────────────────────────────────────────────────
    // MIP-00: KeyPackages
    // ────────────────────────────────────────────────────────────

    /// <summary>
    /// Build a fresh KeyPackage bundle for the given Nostr identity. The
    /// returned bundle is suitable for publishing as a kind-30443
    /// <c>KeyPackageEvent</c> via <see cref="Events.KeyPackageEvent.Create"/>.
    /// Implementations should always include
    /// <see cref="MarmotMlsExtensions.MarmotGroupData"/> in <c>extensions</c>.
    /// </summary>
    Task<KeyPackageBundle> BuildKeyPackageAsync(
        PublicKey identityPubkey,
        ushort ciphersuite,
        IReadOnlyList<ushort> extensions,
        IReadOnlyList<ushort> proposals,
        CancellationToken ct = default);

    /// <summary>
    /// Parse and validate a KeyPackage bundle received from a relay
    /// before using it as the basis for an Add proposal.
    /// </summary>
    Task<KeyPackageInfo> ParseKeyPackageAsync(
        ReadOnlyMemory<byte> keyPackageBundleBytes,
        CancellationToken ct = default);

    // ────────────────────────────────────────────────────────────
    // MIP-01: Group construction
    // ────────────────────────────────────────────────────────────

    /// <summary>
    /// Create a brand-new MLS group with the Marmot Group Data extension
    /// embedded. The provider chooses the 32-byte <c>nostr_group_id</c>
    /// at random and returns it for use in <c>h</c>-tags.
    /// </summary>
    Task<CreateGroupResult> CreateGroupAsync(
        PublicKey creatorPubkey,
        MarmotGroupDataExtension groupData,
        ushort ciphersuite,
        CancellationToken ct = default);

    /// <summary>
    /// Issue an Add proposal + Commit for one or more new members.
    /// </summary>
    /// <returns>
    /// The Commit MLSMessage to broadcast as a kind-445 group event AND a
    /// list of per-recipient Welcome bytes to gift-wrap via
    /// <see cref="Events.WelcomeEvent.Build"/>. Per MIP-02 the Welcome
    /// MUST NOT be sent until the Commit has been accepted by the relay.
    /// </returns>
    Task<AddMembersResult> AddMembersAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        IReadOnlyList<ReadOnlyMemory<byte>> keyPackageBundles,
        CancellationToken ct = default);

    /// <summary>
    /// Process a received Welcome and join the group.
    /// </summary>
    Task<JoinedGroupResult> JoinGroupFromWelcomeAsync(
        ReadOnlyMemory<byte> mlsWelcomeBytes,
        CancellationToken ct = default);

    /// <summary>
    /// Issue Remove proposals + Commit for the specified member pubkeys.
    /// Produces a Commit MLSMessage for existing members to process.
    /// Returns the new exporter secret for the post-removal epoch.
    /// </summary>
    Task<RemoveMembersResult> RemoveMembersAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        IReadOnlyList<PublicKey> peerPubkeys,
        CancellationToken ct = default);

    /// <summary>
    /// Rotate the calling member's leaf keys via an MLS self-update.
    /// Produces a Commit MLSMessage for existing members to process.
    /// Returns the new exporter secret for the post-update epoch.
    /// </summary>
    Task<SelfUpdateResult> SelfUpdateAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        CancellationToken ct = default);

    /// <summary>
    /// Build a SelfRemove proposal (proposal type
    /// <see cref="MarmotMlsProposalTypes.SelfRemove"/>) for the calling member.
    /// </summary>
    Task<byte[]> BuildSelfRemoveProposalAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        CancellationToken ct = default);

    // ────────────────────────────────────────────────────────────
    // MIP-03: Group messaging
    // ────────────────────────────────────────────────────────────

    /// <summary>
    /// Encrypt an application-layer plaintext (typically a Nostr rumor
    /// in JSON form, per MIP-03) into an MLSMessage ready to be wrapped
    /// in a kind-445 event by <see cref="Events.GroupEvent.Build"/>.
    /// </summary>
    Task<byte[]> EncryptApplicationMessageAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        ReadOnlyMemory<byte> plaintext,
        CancellationToken ct = default);

    /// <summary>
    /// Process an incoming MLSMessage — proposal, commit, or application
    /// message. The provider applies state changes; the caller learns
    /// what kind of message it was and recovers any application payload.
    /// </summary>
    Task<ProcessedMlsMessage> ProcessIncomingMlsMessageAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        ReadOnlyMemory<byte> mlsMessageBytes,
        CancellationToken ct = default);

    /// <summary>
    /// Returns the 32-byte MLS exporter secret for the group's current
    /// epoch, derived per MIP-03 with
    /// <c>label = "marmot"</c>, <c>context = "group-event"</c>,
    /// <c>length = 32</c>. This is the symmetric key for kind-445 content.
    /// </summary>
    Task<byte[]> CurrentExporterSecretAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        CancellationToken ct = default);
}

/// <summary>The serialized bytes and metadata of a KeyPackage bundle.</summary>
public sealed record KeyPackageBundle(
    byte[] BundleBytes,
    ushort Ciphersuite,
    string ProtocolVersion,
    string? KeyPackageRef);

/// <summary>Inspectable details of a parsed KeyPackage bundle.</summary>
public sealed record KeyPackageInfo(
    PublicKey IdentityPubkey,
    ushort Ciphersuite,
    string ProtocolVersion,
    IReadOnlyList<ushort> Extensions,
    IReadOnlyList<ushort> Proposals,
    string? KeyPackageRef);

/// <summary>The output of creating a brand-new MLS group.</summary>
/// <param name="NostrGroupId">The 32-byte id, populated into the Marmot Group Data extension and group-event <c>h</c>-tags.</param>
/// <param name="InitialExporterSecret">The exporter secret for epoch 0.</param>
public sealed record CreateGroupResult(
    byte[] NostrGroupId,
    byte[] InitialExporterSecret);

/// <summary>The two-part output of an Add+Commit.</summary>
/// <param name="CommitMlsMessageBytes">Serialized MLSMessage to publish via a kind-445 group event.</param>
/// <param name="Welcomes">Per-recipient Welcome bytes to gift-wrap, in the same order as the input KeyPackages.</param>
/// <param name="NewExporterSecret">The exporter secret for the epoch produced by the Commit.</param>
public sealed record AddMembersResult(
    byte[] CommitMlsMessageBytes,
    IReadOnlyList<WelcomeToSend> Welcomes,
    byte[] NewExporterSecret);

/// <summary>The output of a Remove+Commit (no Welcomes — nothing is being added).</summary>
/// <param name="CommitMlsMessageBytes">Serialized MLSMessage to publish via a kind-445 group event so existing members process the removal.</param>
/// <param name="NewExporterSecret">Exporter for the post-removal epoch.</param>
public sealed record RemoveMembersResult(
    byte[] CommitMlsMessageBytes,
    byte[] NewExporterSecret);

/// <summary>The output of a self-update Commit (local member rotates their leaf keys).</summary>
/// <param name="CommitMlsMessageBytes">Serialized MLSMessage to publish via a kind-445 group event.</param>
/// <param name="NewExporterSecret">Exporter for the post-update epoch.</param>
public sealed record SelfUpdateResult(
    byte[] CommitMlsMessageBytes,
    byte[] NewExporterSecret);

/// <summary>A Welcome blob targeted at a specific recipient identity.</summary>
public sealed record WelcomeToSend(
    PublicKey RecipientPubkey,
    byte[] WelcomeMlsMessageBytes);

/// <summary>The result of joining a group via a received Welcome.</summary>
public sealed record JoinedGroupResult(
    byte[] NostrGroupId,
    MarmotGroupDataExtension GroupData,
    byte[] CurrentExporterSecret);

/// <summary>Classification of a processed inbound MLSMessage.</summary>
public enum MlsMessageKind
{
    /// <summary>An application message (kind-445 plaintext payload available).</summary>
    Application,

    /// <summary>A proposal that's been queued but not yet committed.</summary>
    Proposal,

    /// <summary>A commit that advanced the group's epoch.</summary>
    Commit,
}

/// <summary>The outcome of <see cref="IMarmotMlsProvider.ProcessIncomingMlsMessageAsync"/>.</summary>
/// <param name="Kind">The classification of this MLSMessage.</param>
/// <param name="ApplicationPayload">For <see cref="MlsMessageKind.Application"/>, the decrypted plaintext; otherwise empty.</param>
/// <param name="EpochAdvanced"><c>true</c> if a new MLS epoch is now active; the caller should refresh the exporter secret if encrypting outbound traffic.</param>
/// <param name="NewExporterSecret">When <paramref name="EpochAdvanced"/> is true, the new exporter secret; otherwise <c>null</c>.</param>
/// <param name="Sender">
/// For Application and Commit messages, the Nostr pubkey of the
/// member who produced this message (resolved via OpenMLS's leaf-index
/// → BasicCredential lookup at processing time, BEFORE any commit is
/// applied). <c>null</c> for proposals, external senders, or messages
/// whose sender can't be resolved.
/// </param>
public sealed record ProcessedMlsMessage(
    MlsMessageKind Kind,
    byte[] ApplicationPayload,
    bool EpochAdvanced,
    byte[]? NewExporterSecret,
    PublicKey? Sender = null);
