// SPDX-License-Identifier: MIT

namespace NostrNet.Relay.Storage;

/// <summary>
/// Disposition returned by <see cref="INostrEventStore.StoreAsync"/>.
/// Tells the caller whether the event was accepted and what happened to
/// any prior versions.
/// </summary>
public enum StoreResult
{
    /// <summary>The event was new and was added to the store.</summary>
    Stored,

    /// <summary>
    /// The event was a newer NIP-01 replaceable or parameterized-replaceable
    /// version of one already in the store; the older one was evicted.
    /// </summary>
    Replaced,

    /// <summary>
    /// An event with this id was already in the store; the new copy was discarded.
    /// </summary>
    Duplicate,

    /// <summary>
    /// The event was an older NIP-01 replaceable or parameterized-replaceable
    /// version than one already in the store; it was discarded.
    /// </summary>
    Outdated,

    /// <summary>
    /// A prior NIP-09 deletion request from the same author covers this event;
    /// it was discarded.
    /// </summary>
    Deleted,

    /// <summary>
    /// The event carried a NIP-40 <c>expiration</c> tag whose value is in
    /// the past; it was discarded.
    /// </summary>
    Expired,

    /// <summary>
    /// The event was an NIP-01 ephemeral kind (20000–29999). It was fanned
    /// out to live <see cref="INostrEventStore.ObserveAsync"/> subscribers
    /// but not persisted — ephemeral events are transient by spec and
    /// would otherwise crowd out durable events under capacity pressure.
    /// </summary>
    Ephemeral,
}
