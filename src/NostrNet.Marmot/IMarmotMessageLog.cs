// SPDX-License-Identifier: MIT

using NostrNet.Keys;

namespace NostrNet.Marmot;

/// <summary>
/// Optional plaintext-message persistence for Marmot. MLS deliberately
/// destroys old exporters as the epoch advances, so kind-445 ciphertext
/// on relays becomes permanently undecryptable once the group has moved
/// past the epoch that produced it. Anything you want to render on a
/// future cold start — chat history, chat-list previews, last-activity
/// timestamps — has to be captured at the moment the message is
/// decrypted.
/// </summary>
/// <remarks>
/// <para>
/// Wire <see cref="NostrMarmotClientBuilder.WithMessageLog"/> to plug in
/// an implementation. The client appends every successfully-decrypted
/// application message (kind-445 with
/// <see cref="MarmotMessageKind.Application"/>) to the log automatically.
/// Apps read back via <see cref="NostrMarmotClient.LoadHistoryAsync"/>
/// and <see cref="NostrMarmotClient.GetLastMessageAsync"/>.
/// </para>
/// <para>
/// Implementations decide persistence (in-memory, SQLite, Realm,
/// encrypted-at-rest, etc.). The interface is intentionally small so
/// any backend works. Calls must be safe to invoke concurrently —
/// the receive pump appends from background threads and apps read
/// from UI threads.
/// </para>
/// <para>
/// Spec / layering: the log holds <em>plaintext</em>, not MLS state.
/// Treat it the same way you'd treat an email "sent folder": data the
/// user can read and that should be encrypted-at-rest in any backend
/// that touches disk.
/// </para>
/// </remarks>
public interface IMarmotMessageLog
{
    /// <summary>
    /// Append a decrypted application message. Implementations should dedup
    /// on <see cref="MarmotMessageReceived.EventId"/> because the same
    /// kind-445 event can be delivered by multiple relays during one
    /// session — both deliveries decrypt to the same plaintext and the
    /// log shouldn't store the message twice.
    /// </summary>
    ValueTask AppendAsync(MarmotMessageReceived message, CancellationToken cancellationToken = default);

    /// <summary>
    /// Read persisted application messages for <paramref name="nostrGroupId"/>,
    /// oldest-first. Filters by <paramref name="since"/> (inclusive lower bound
    /// on <see cref="MarmotMessageReceived.ServerTimestamp"/>) and caps at
    /// <paramref name="limit"/> when non-null.
    /// </summary>
    IAsyncEnumerable<MarmotMessageReceived> LoadAsync(
        byte[] nostrGroupId,
        DateTimeOffset? since = null,
        int? limit = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// The most recent persisted application message for the group, or
    /// <c>null</c> when none is stored. Useful for chat-list previews and
    /// last-activity timestamps without paging history.
    /// </summary>
    ValueTask<MarmotMessageReceived?> GetLastAsync(
        byte[] nostrGroupId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Drop every message for the given group. Call this after a clean
    /// leave (<see cref="IMarmotMlsProvider.DeleteGroupAsync"/>) or a
    /// "delete chat" UI action so the log doesn't outlive the MLS state.
    /// Idempotent — deleting an unknown group is a no-op.
    /// </summary>
    ValueTask DeleteGroupAsync(byte[] nostrGroupId, CancellationToken cancellationToken = default);
}
