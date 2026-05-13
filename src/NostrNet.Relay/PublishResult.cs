// SPDX-License-Identifier: MIT

namespace NostrNet.Relay;

/// <summary>
/// The relay's response to a <see cref="IRelayClient.PublishAsync"/> call.
/// </summary>
/// <param name="Accepted">Whether the relay accepted the event.</param>
/// <param name="Message">A human-readable reason; on rejection often a NIP-20 prefix such as <c>blocked:</c> or <c>invalid:</c>.</param>
public sealed record PublishResult(bool Accepted, string Message);
