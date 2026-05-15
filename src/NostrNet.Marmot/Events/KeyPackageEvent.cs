// SPDX-License-Identifier: MIT
//
// MIP-00 KeyPackage event (kind 30443).
//
// A parameterized-replaceable event acting as a public "invitation card":
// it advertises a user's MLS capabilities and carries a TLS-serialized
// KeyPackageBundle (base64-encoded in the event's `content`) that other
// users can consume to add this user to a group.
//
// This module handles the Nostr-side envelope only — the bundle bytes are
// opaque to NostrNet. The actual KeyPackageBundle construction (signing
// keys, LeafNode capabilities, the TLS-serialized KeyPackage struct) is
// the job of an external MLS provider (see IMarmotMlsProvider).

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Marmot.Events;

/// <summary>
/// A typed view of a kind-30443 KeyPackage event (MIP-00).
/// </summary>
public sealed class KeyPackageEvent : INostrTypedEvent<KeyPackageEvent>
{
    /// <summary>Nostr kind(s) this type represents.</summary>
    public static IReadOnlyList<int> Kinds { get; } = new[] { MarmotKinds.KeyPackage };

    /// <summary>Author pubkey (the user this KeyPackage represents).</summary>
    public required PublicKey Author { get; init; }

    /// <summary>The KeyPackage slot identifier (the <c>d</c>-tag value).</summary>
    public required string Identifier { get; init; }

    /// <summary>The event's <c>created_at</c>.</summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>
    /// Raw TLS-serialized <c>KeyPackageBundle</c> bytes, decoded from the
    /// event's base64 content. Opaque to NostrNet — pass to your MLS provider.
    /// </summary>
    public required byte[] KeyPackageBundleBytes { get; init; }

    /// <summary>MLS protocol version string (e.g. <c>"1.0"</c>).</summary>
    public required string MlsProtocolVersion { get; init; }

    /// <summary>MLS ciphersuite identifier (e.g. <c>"0x0001"</c>).</summary>
    public required string MlsCiphersuite { get; init; }

    /// <summary>Non-default MLS extension IDs supported by this client (e.g. <c>"0xf2ee"</c>, <c>"0x000a"</c>).</summary>
    public IReadOnlyList<string> MlsExtensions { get; init; } = Array.Empty<string>();

    /// <summary>Non-default MLS proposal type IDs supported (e.g. <c>"0x000a"</c>).</summary>
    public IReadOnlyList<string> MlsProposals { get; init; } = Array.Empty<string>();

    /// <summary>Hex-encoded MLS <c>KeyPackageRef</c> for efficient relay queries.</summary>
    public string? KeyPackageRef { get; init; }

    /// <summary>Relay URLs where this KeyPackage is published.</summary>
    public IReadOnlyList<string> Relays { get; init; } = Array.Empty<string>();

    /// <summary>Optional client-name UX hint.</summary>
    public string? Client { get; init; }

    /// <summary>Parses a kind-30443 Nostr event into a typed KeyPackage view.</summary>
    /// <exception cref="ArgumentException">The event is not kind 30443.</exception>
    /// <exception cref="FormatException">A required tag is missing or the content is not valid base64.</exception>
    public static KeyPackageEvent FromEvent(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);
        if (ev.Kind != MarmotKinds.KeyPackage)
        {
            throw new ArgumentException(
                $"Expected a Marmot KeyPackage kind ({MarmotKinds.KeyPackage}); got {ev.Kind}.",
                nameof(ev));
        }

        string? identifier = ev.Tags.Identifier();
        if (string.IsNullOrEmpty(identifier))
        {
            throw new FormatException("KeyPackage event is missing the required 'd' tag.");
        }

        string encoding = ev.Tags.FirstValue("encoding")
            ?? throw new FormatException("KeyPackage event is missing the required 'encoding' tag.");
        if (!string.Equals(encoding, "base64", StringComparison.Ordinal))
        {
            throw new FormatException($"KeyPackage 'encoding' must be 'base64'; got '{encoding}' (hex is no longer supported per MIP-00).");
        }

        byte[] bundleBytes;
        try
        {
            bundleBytes = Convert.FromBase64String(ev.Content);
        }
        catch (FormatException ex)
        {
            throw new FormatException("KeyPackage content is not valid base64.", ex);
        }

        string protocolVersion = ev.Tags.FirstValue("mls_protocol_version")
            ?? throw new FormatException("KeyPackage event is missing 'mls_protocol_version'.");
        string ciphersuite = ev.Tags.FirstValue("mls_ciphersuite")
            ?? throw new FormatException("KeyPackage event is missing 'mls_ciphersuite'.");

        var extensions = ev.Tags
            .FirstWithName("mls_extensions")
            ?.Skip(1)
            .ToArray() ?? Array.Empty<string>();

        var proposals = ev.Tags
            .FirstWithName("mls_proposals")
            ?.Skip(1)
            .ToArray() ?? Array.Empty<string>();

        var relays = ev.Tags
            .FirstWithName("relays")
            ?.Skip(1)
            .ToArray() ?? Array.Empty<string>();

        return new KeyPackageEvent
        {
            Author = ev.PubKey,
            Identifier = identifier,
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(ev.CreatedAt),
            KeyPackageBundleBytes = bundleBytes,
            MlsProtocolVersion = protocolVersion,
            MlsCiphersuite = ciphersuite,
            MlsExtensions = extensions,
            MlsProposals = proposals,
            KeyPackageRef = ev.Tags.FirstValue("i"),
            Relays = relays,
            Client = ev.Tags.FirstValue("client"),
        };
    }

    /// <summary>Try-parse variant. Returns <c>false</c> on the wrong kind or malformed content.</summary>
    public static bool TryFromEvent(NostrEvent? ev, [NotNullWhen(true)] out KeyPackageEvent? keyPackage)
    {
        keyPackage = null;
        if (ev is null)
        {
            return false;
        }

        try
        {
            keyPackage = FromEvent(ev);
            return true;
        }
        catch (Exception e) when (e is ArgumentException or FormatException)
        {
            return false;
        }
    }

    /// <summary>Returns the NIP-19 <c>naddr</c> coordinate for this KeyPackage.</summary>
    public Nip19.NaddrEntity ToNaddr(IReadOnlyList<string>? relays = null)
        => new()
        {
            PubKey = Author,
            Kind = MarmotKinds.KeyPackage,
            Identifier = Identifier,
            Relays = relays ?? Relays,
        };

    /// <summary>
    /// Starts building a new KeyPackage event for the given identifier slot.
    /// The slot is the <c>d</c>-tag value; reusing it rotates this slot
    /// (replaceability).
    /// </summary>
    public static KeyPackageEventBuilder Create(string identifier) => new(identifier);
}

/// <summary>Fluent builder for kind-30443 KeyPackage events.</summary>
public sealed class KeyPackageEventBuilder
{
    private readonly string _identifier;
    private byte[]? _bundleBytes;
    private string _mlsProtocolVersion = "1.0";
    private string? _mlsCiphersuite;
    private readonly List<string> _extensions = new();
    private readonly List<string> _proposals = new();
    private string? _keyPackageRef;
    private readonly List<string> _relays = new();
    private string? _client;

    internal KeyPackageEventBuilder(string identifier)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);
        _identifier = identifier;
    }

    /// <summary>Sets the TLS-serialized KeyPackageBundle bytes (opaque to this library).</summary>
    public KeyPackageEventBuilder WithBundleBytes(byte[] bundleBytes)
    {
        ArgumentNullException.ThrowIfNull(bundleBytes);
        _bundleBytes = bundleBytes;
        return this;
    }

    /// <summary>Sets the <c>mls_protocol_version</c> tag (defaults to <c>"1.0"</c>).</summary>
    public KeyPackageEventBuilder WithProtocolVersion(string version)
    {
        _mlsProtocolVersion = version;
        return this;
    }

    /// <summary>Sets the <c>mls_ciphersuite</c> tag value (e.g. <c>"0x0001"</c>).</summary>
    public KeyPackageEventBuilder WithCiphersuite(string ciphersuiteId)
    {
        _mlsCiphersuite = ciphersuiteId;
        return this;
    }

    /// <summary>Convenience: format an integer ciphersuite ID as <c>"0xNNNN"</c>.</summary>
    public KeyPackageEventBuilder WithCiphersuite(ushort ciphersuiteId)
        => WithCiphersuite("0x" + ciphersuiteId.ToString("x4", CultureInfo.InvariantCulture));

    /// <summary>Adds a non-default MLS extension ID this KeyPackage advertises (e.g. <c>"0xf2ee"</c>).</summary>
    public KeyPackageEventBuilder WithExtension(string extensionId)
    {
        _extensions.Add(extensionId);
        return this;
    }

    /// <summary>Adds a non-default MLS extension ID formatted as <c>"0xNNNN"</c>.</summary>
    public KeyPackageEventBuilder WithExtension(ushort extensionId)
        => WithExtension("0x" + extensionId.ToString("x4", CultureInfo.InvariantCulture));

    /// <summary>Adds a non-default MLS proposal type ID this KeyPackage advertises.</summary>
    public KeyPackageEventBuilder WithProposal(string proposalId)
    {
        _proposals.Add(proposalId);
        return this;
    }

    /// <summary>Adds a non-default MLS proposal type ID formatted as <c>"0xNNNN"</c>.</summary>
    public KeyPackageEventBuilder WithProposal(ushort proposalId)
        => WithProposal("0x" + proposalId.ToString("x4", CultureInfo.InvariantCulture));

    /// <summary>Sets the hex-encoded KeyPackageRef for efficient relay queries.</summary>
    public KeyPackageEventBuilder WithKeyPackageRef(string hexRef)
    {
        _keyPackageRef = hexRef;
        return this;
    }

    /// <summary>Adds a relay URL where this KeyPackage is published.</summary>
    public KeyPackageEventBuilder WithRelay(string url)
    {
        _relays.Add(url);
        return this;
    }

    /// <summary>Adds multiple relay URLs.</summary>
    public KeyPackageEventBuilder WithRelays(params string[] urls)
    {
        _relays.AddRange(urls);
        return this;
    }

    /// <summary>Optional client-name UX hint.</summary>
    public KeyPackageEventBuilder WithClient(string clientName)
    {
        _client = clientName;
        return this;
    }

    /// <summary>Builds and signs the KeyPackage event.</summary>
    /// <exception cref="InvalidOperationException">A required field hasn't been set.</exception>
    public NostrEvent Sign(PrivateKey key, long? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (_bundleBytes is null)
        {
            throw new InvalidOperationException(
                "KeyPackage bundle bytes are required. Call WithBundleBytes() with TLS-serialized data from your MLS provider.");
        }

        if (_mlsCiphersuite is null)
        {
            throw new InvalidOperationException("Ciphersuite is required. Call WithCiphersuite().");
        }

        if (_relays.Count == 0)
        {
            throw new InvalidOperationException(
                "At least one relay URL is required per MIP-00 — this is how peers discover the KeyPackage.");
        }

        var tags = new List<IReadOnlyList<string>>
        {
            Tag.D(_identifier),
            new[] { "mls_protocol_version", _mlsProtocolVersion },
            new[] { "mls_ciphersuite", _mlsCiphersuite },
        };

        if (_extensions.Count > 0)
        {
            var ext = new List<string>(1 + _extensions.Count) { "mls_extensions" };
            ext.AddRange(_extensions);
            tags.Add(ext);
        }

        if (_proposals.Count > 0)
        {
            var prop = new List<string>(1 + _proposals.Count) { "mls_proposals" };
            prop.AddRange(_proposals);
            tags.Add(prop);
        }

        tags.Add(new[] { "encoding", "base64" });

        if (_keyPackageRef is not null)
        {
            tags.Add(new[] { "i", _keyPackageRef });
        }

        if (_client is not null)
        {
            tags.Add(new[] { "client", _client });
        }

        var relayTag = new List<string>(1 + _relays.Count) { "relays" };
        relayTag.AddRange(_relays);
        tags.Add(relayTag);

        return new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = MarmotKinds.KeyPackage,
            Tags = tags,
            Content = Convert.ToBase64String(_bundleBytes),
        }.Sign(key);
    }
}
