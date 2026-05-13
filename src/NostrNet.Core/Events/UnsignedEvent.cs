// SPDX-License-Identifier: MIT

using NostrNet.Cryptography;
using NostrNet.Keys;

namespace NostrNet.Events;

/// <summary>
/// An event that has all its content fields set but is not yet signed.
/// </summary>
/// <remarks>
/// Calling <see cref="Sign"/> produces a <see cref="NostrEvent"/>. The relay
/// client only accepts signed events for publication, so it is not possible to
/// accidentally publish an unsigned event.
/// </remarks>
public sealed class UnsignedEvent
{
    /// <summary>The author's x-only public key.</summary>
    public required PublicKey PubKey { get; init; }

    /// <summary>
    /// Unix timestamp in seconds. Convention: caller supplies this; the library
    /// does not default it from <see cref="DateTimeOffset.UtcNow"/>.
    /// </summary>
    public required long CreatedAt { get; init; }

    /// <summary>The NIP-01 event kind.</summary>
    public required int Kind { get; init; }

    /// <summary>
    /// Tag rows. Each row is an array of strings; the first element is the tag
    /// name, the remainder are tag values. Empty list (not null) for no tags.
    /// </summary>
    public required IReadOnlyList<IReadOnlyList<string>> Tags { get; init; }

    /// <summary>The event content string.</summary>
    public required string Content { get; init; }

    /// <summary>
    /// Computes the NIP-01 event id (SHA-256 of the canonical serialization)
    /// without signing.
    /// </summary>
    public EventId ComputeId() => EventSerializer.ComputeId(PubKey, CreatedAt, Kind, Tags, Content);

    /// <summary>
    /// Signs this event with the provided private key and returns the
    /// resulting <see cref="NostrEvent"/>.
    /// </summary>
    /// <param name="key">The signing private key. Its public key must match <see cref="PubKey"/>.</param>
    /// <param name="auxRand">
    /// Optional 32 bytes of fresh randomness for BIP-340 §3.3.1 probabilistic
    /// signing. Empty (the default) selects deterministic signing.
    /// </param>
    /// <exception cref="ArgumentException">The key's public key does not match <see cref="PubKey"/>.</exception>
    public NostrEvent Sign(PrivateKey key, ReadOnlySpan<byte> auxRand = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (!key.PublicKey.Equals(PubKey))
        {
            throw new ArgumentException("Private key does not match the event's PubKey.", nameof(key));
        }

        EventId id = ComputeId();

        Span<byte> sig = stackalloc byte[Signature.Size];
        key.Sign(id.AsSpan(), sig, auxRand);

        return new NostrEvent
        {
            Id = id,
            PubKey = PubKey,
            CreatedAt = CreatedAt,
            Kind = Kind,
            Tags = Tags,
            Content = Content,
            Sig = new Signature(sig),
        };
    }
}
