// SPDX-License-Identifier: MIT

using System.Diagnostics.CodeAnalysis;

namespace NostrNet.Events;

/// <summary>
/// Marker for a strongly-typed wrapper around a Nostr event of one or
/// more specific kinds. Used by generic store APIs like
/// <c>store.ObserveAsync&lt;Profile&gt;()</c> and
/// <c>store.QueryAsync&lt;Article&gt;()</c> to translate raw events
/// into typed values automatically.
/// </summary>
/// <remarks>
/// <para>
/// Implementers expose two static-abstract members:
/// </para>
/// <list type="bullet">
///   <item><see cref="Kinds"/> — the Nostr kind(s) this type represents.
///         Defaulted onto the underlying <c>Filter</c> when the caller
///         does not specify kinds explicitly.</item>
///   <item><see cref="TryFromEvent"/> — non-throwing constructor that
///         returns <c>false</c> when an event of the expected kind is
///         malformed (missing required tags, unparseable content, etc.).
///         The store silently skips events that fail to convert.</item>
/// </list>
/// <para>
/// Fully AOT-safe — each <c>store.ObserveAsync&lt;T&gt;</c> instantiation
/// resolves to a closed generic at compile time; no reflection, no
/// registration, no runtime type registry.
/// </para>
/// </remarks>
public interface INostrTypedEvent<TSelf> where TSelf : INostrTypedEvent<TSelf>
{
    /// <summary>
    /// The Nostr <c>kind</c>(s) this type represents. Returned as a
    /// non-empty, read-only list — implementations typically expose a
    /// single cached array so this property is allocation-free at call
    /// sites.
    /// </summary>
    static abstract IReadOnlyList<int> Kinds { get; }

    /// <summary>
    /// Attempts to construct a <typeparamref name="TSelf"/> from
    /// <paramref name="ev"/>. Returns <c>false</c> without throwing
    /// when the event does not match the expected shape (wrong kind,
    /// missing required tags, malformed content, etc.) or when
    /// <paramref name="ev"/> is null.
    /// </summary>
    /// <param name="ev">The raw Nostr event to convert; <c>null</c> returns <c>false</c>.</param>
    /// <param name="value">The typed value on success; <c>null</c> on failure.</param>
    /// <returns><c>true</c> when conversion succeeded; <c>false</c> otherwise.</returns>
    static abstract bool TryFromEvent(NostrEvent? ev, [NotNullWhen(true)] out TSelf? value);
}
