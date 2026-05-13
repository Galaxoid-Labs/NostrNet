// SPDX-License-Identifier: MIT

using NostrNet.Events;

namespace NostrNet.Relay;

/// <summary>
/// Base class for events delivered on a relay subscription stream.
/// </summary>
public abstract record SubscriptionEvent;

/// <summary>An event matching the subscription's filters was delivered.</summary>
public sealed record SubscriptionEventReceived(NostrEvent Event) : SubscriptionEvent;

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
