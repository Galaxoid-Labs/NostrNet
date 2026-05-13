// SPDX-License-Identifier: MIT

using NostrNet.Events;

namespace NostrNet.Client;

/// <summary>
/// An event received from a specific relay during a subscription.
/// </summary>
/// <param name="Event">The verified Nostr event.</param>
/// <param name="Relay">The relay that delivered this occurrence.</param>
/// <remarks>
/// When subscribing across a pool, the same event id may be delivered by
/// multiple relays. Each delivery is yielded as its own
/// <see cref="ReceivedEvent"/> — the consumer chooses whether to dedup,
/// store, or aggregate "which relays carried this event" themselves.
/// </remarks>
public sealed record ReceivedEvent(NostrEvent Event, Uri Relay);
