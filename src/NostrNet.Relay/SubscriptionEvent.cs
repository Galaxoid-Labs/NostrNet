// SPDX-License-Identifier: MIT

using NostrNet.Events;

namespace NostrNet.Relay;

/// <summary>
/// Base class for events delivered on a relay subscription stream.
/// </summary>
public abstract record SubscriptionEvent;

/// <summary>An event matching the subscription's filters was delivered.</summary>
/// <param name="Event">The verified Nostr event (id + signature already checked).</param>
/// <param name="Relay">The relay this occurrence was received from. When the same event is carried by multiple relays, each relay's delivery is yielded as its own <see cref="SubscriptionEventReceived"/> — consumers that want a single occurrence per event id should dedup explicitly.</param>
public sealed record SubscriptionEventReceived(NostrEvent Event, Uri Relay) : SubscriptionEvent;

/// <summary>
/// The relay has finished delivering stored events; any further events on
/// this subscription will be live.
/// </summary>
public sealed record SubscriptionEndOfStoredEvents : SubscriptionEvent;

/// <summary>
/// The relay closed the subscription (e.g., quota reached, AUTH required).
/// The stream terminates after this message.
/// </summary>
public sealed record SubscriptionClosed(string Reason) : SubscriptionEvent;
