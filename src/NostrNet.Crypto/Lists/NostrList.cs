// SPDX-License-Identifier: MIT
//
// NIP-51 list reader and builder.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/51.md
//
// A NIP-51 list event has two halves:
//   - Public items: ordinary tags on the event.
//   - Private items: a JSON array of tag-arrays, NIP-44 self-encrypted in
//     the event's content field. Self-encryption means the conversation key
//     is computed with the author's own private + public key on both sides.
//
// This module supports the modern NIP-44 path only. Lists encrypted with
// the legacy NIP-04 scheme (used by older clients) won't decrypt; the
// public items will still be readable.

using System.Text.Encodings.Web;
using System.Text.Json;
using NostrNet.Crypto;
using NostrNet.Events;
using NostrNet.Keys;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Lists;

/// <summary>
/// A typed view over a NIP-51 list event. Exposes both public (in-tag) and
/// private (NIP-44 self-encrypted) items, plus convenience accessors for
/// each common tag name.
/// </summary>
public sealed class NostrList
{
    /// <summary>The event kind (see <see cref="Nip51Kinds"/>).</summary>
    public required int Kind { get; init; }

    /// <summary>The author of the list event.</summary>
    public required PublicKey Owner { get; init; }

    /// <summary>The <c>"d"</c> tag value for parameterized sets, or <c>null</c> for plain lists.</summary>
    public string? Identifier { get; init; }

    /// <summary>The list's title (if a <c>"title"</c> tag is present).</summary>
    public string? Title { get; init; }

    /// <summary>The list's description (if a <c>"description"</c> tag is present).</summary>
    public string? Description { get; init; }

    /// <summary>The list's image URL (if an <c>"image"</c> tag is present).</summary>
    public string? Image { get; init; }

    /// <summary>The public items, as the event's tag rows (excluding metadata tags).</summary>
    public required IReadOnlyList<IReadOnlyList<string>> PublicItems { get; init; }

    /// <summary>
    /// The private items, decrypted from the event's content. Empty if the
    /// event has no private content, or if the list was loaded without an
    /// owner key.
    /// </summary>
    public IReadOnlyList<IReadOnlyList<string>> PrivateItems { get; init; }
        = Array.Empty<IReadOnlyList<string>>();

    /// <summary>True if the event's content field carries encrypted private items.</summary>
    public bool HasEncryptedContent { get; init; }

    /// <summary>All items (public + private) combined for traversal.</summary>
    public IEnumerable<IReadOnlyList<string>> AllItems => PublicItems.Concat(PrivateItems);

    /// <summary>Every <c>"p"</c>-tagged pubkey across public and private items.</summary>
    public IEnumerable<PublicKey> Pubkeys
    {
        get
        {
            foreach (var p in ((IReadOnlyList<IReadOnlyList<string>>)PublicItems.ToList()).Pubkeys())
            {
                yield return p;
            }

            foreach (var p in ((IReadOnlyList<IReadOnlyList<string>>)PrivateItems.ToList()).Pubkeys())
            {
                yield return p;
            }
        }
    }

    /// <summary>Every <c>"e"</c>-tagged event id across public and private items.</summary>
    public IEnumerable<EventId> EventIds
        => MaterializedPublic.EventIds().Concat(MaterializedPrivate.EventIds());

    /// <summary>Every <c>"t"</c>-tagged hashtag across public and private items.</summary>
    public IEnumerable<string> Hashtags
        => MaterializedPublic.Hashtags().Concat(MaterializedPrivate.Hashtags());

    /// <summary>Every <c>"word"</c>-tagged muted word across public and private items.</summary>
    public IEnumerable<string> Words
        => MaterializedPublic.AllValues("word").Concat(MaterializedPrivate.AllValues("word"));

    /// <summary>Every <c>"relay"</c>-tagged URL across public and private items.</summary>
    public IEnumerable<string> Relays
        => MaterializedPublic.AllValues("relay").Concat(MaterializedPrivate.AllValues("relay"));

    /// <summary>Every <c>"a"</c>-tagged coordinate string across public and private items.</summary>
    public IEnumerable<string> AddressableCoordinates
        => MaterializedPublic.AllValues("a").Concat(MaterializedPrivate.AllValues("a"));

    private IReadOnlyList<IReadOnlyList<string>> MaterializedPublic => PublicItems;
    private IReadOnlyList<IReadOnlyList<string>> MaterializedPrivate => PrivateItems;

    /// <summary>
    /// Parses a NIP-51 list event into a <see cref="NostrList"/>. Private
    /// items remain encrypted (and the <see cref="PrivateItems"/> list is
    /// empty) — use the overload taking <see cref="PrivateKey"/> to decrypt.
    /// </summary>
    public static NostrList FromEvent(NostrEvent listEvent)
    {
        ArgumentNullException.ThrowIfNull(listEvent);
        return Build(listEvent, ownerKey: null);
    }

    /// <summary>
    /// Parses a NIP-51 list event and decrypts its private items using
    /// <paramref name="ownerKey"/> (which must be the event author's key).
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="ownerKey"/>'s public key does not match the event author.</exception>
    public static NostrList FromEvent(NostrEvent listEvent, PrivateKey ownerKey)
    {
        ArgumentNullException.ThrowIfNull(listEvent);
        ArgumentNullException.ThrowIfNull(ownerKey);
        if (!ownerKey.PublicKey.Equals(listEvent.PubKey))
        {
            throw new ArgumentException(
                "ownerKey does not correspond to the list event's author.",
                nameof(ownerKey));
        }

        return Build(listEvent, ownerKey);
    }

    /// <summary>
    /// Starts building a new NIP-51 list event of the given <paramref name="kind"/>.
    /// </summary>
    /// <param name="kind">A list or set kind (see <see cref="Nip51Kinds"/>).</param>
    /// <param name="identifier">
    /// Required for parameterized sets (kind ≥ 30000). Ignored for plain
    /// replaceable lists.
    /// </param>
    public static NostrListBuilder Create(int kind, string? identifier = null)
    {
        if (Nip51Kinds.IsParameterizedSet(kind) && string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(
                $"Kind {kind} is a parameterized set and requires a non-empty identifier.",
                nameof(identifier));
        }

        return new NostrListBuilder(kind, identifier);
    }

    private static NostrList Build(NostrEvent ev, PrivateKey? ownerKey)
    {
        // Separate metadata tags (d, title, description, image) from item tags.
        string? identifier = null;
        string? title = null;
        string? description = null;
        string? image = null;
        var items = new List<IReadOnlyList<string>>(ev.Tags.Count);

        foreach (var tag in ev.Tags)
        {
            if (tag.Count == 0)
            {
                continue;
            }

            switch (tag[0])
            {
                case "d" when tag.Count >= 2:
                    identifier ??= tag[1];
                    break;
                case "title" when tag.Count >= 2:
                    title ??= tag[1];
                    break;
                case "description" when tag.Count >= 2:
                    description ??= tag[1];
                    break;
                case "image" when tag.Count >= 2:
                    image ??= tag[1];
                    break;
                default:
                    items.Add(tag);
                    break;
            }
        }

        bool hasEncrypted = !string.IsNullOrEmpty(ev.Content);
        IReadOnlyList<IReadOnlyList<string>> privateItems = Array.Empty<IReadOnlyList<string>>();

        if (hasEncrypted && ownerKey is not null)
        {
            try
            {
                string plaintext = Nip44.Decrypt(ev.Content, ownerKey, ownerKey.PublicKey);
                privateItems = ParseTagArray(plaintext);
            }
            catch
            {
                // Likely NIP-04 encrypted (older clients) or otherwise undecryptable.
                // Leave PrivateItems empty; the public items are still usable.
                privateItems = Array.Empty<IReadOnlyList<string>>();
            }
        }

        return new NostrList
        {
            Kind = ev.Kind,
            Owner = ev.PubKey,
            Identifier = identifier,
            Title = title,
            Description = description,
            Image = image,
            PublicItems = items,
            PrivateItems = privateItems,
            HasEncryptedContent = hasEncrypted,
        };
    }

    private static IReadOnlyList<IReadOnlyList<string>> ParseTagArray(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<IReadOnlyList<string>>();
        }

        var result = new List<IReadOnlyList<string>>(doc.RootElement.GetArrayLength());
        foreach (var tagEl in doc.RootElement.EnumerateArray())
        {
            if (tagEl.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            var tag = new List<string>(tagEl.GetArrayLength());
            foreach (var v in tagEl.EnumerateArray())
            {
                tag.Add(v.GetString() ?? string.Empty);
            }

            result.Add(tag);
        }

        return result;
    }

    internal static string SerializeTagArray(IReadOnlyList<IReadOnlyList<string>> tags)
    {
        using var ms = new MemoryStream();
        var options = new JsonWriterOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            SkipValidation = false,
            Indented = false,
        };

        using (var writer = new Utf8JsonWriter(ms, options))
        {
            writer.WriteStartArray();
            foreach (var tag in tags)
            {
                writer.WriteStartArray();
                foreach (var v in tag)
                {
                    writer.WriteStringValue(v);
                }

                writer.WriteEndArray();
            }

            writer.WriteEndArray();
        }

        return SysEncoding.UTF8.GetString(ms.ToArray());
    }
}

/// <summary>
/// Fluent builder for NIP-51 list events. Add public items (visible to
/// anyone who fetches the event) and/or private items (NIP-44 self-encrypted
/// in the event's content field).
/// </summary>
public sealed class NostrListBuilder
{
    private readonly int _kind;
    private readonly string? _identifier;
    private readonly List<IReadOnlyList<string>> _publicItems = new();
    private readonly List<IReadOnlyList<string>> _privateItems = new();
    private string? _title;
    private string? _description;
    private string? _image;

    internal NostrListBuilder(int kind, string? identifier)
    {
        _kind = kind;
        _identifier = identifier;
    }

    /// <summary>Sets the list's <c>"title"</c> metadata tag.</summary>
    public NostrListBuilder WithTitle(string title)
    {
        _title = title ?? throw new ArgumentNullException(nameof(title));
        return this;
    }

    /// <summary>Sets the list's <c>"description"</c> metadata tag.</summary>
    public NostrListBuilder WithDescription(string description)
    {
        _description = description ?? throw new ArgumentNullException(nameof(description));
        return this;
    }

    /// <summary>Sets the list's <c>"image"</c> metadata tag.</summary>
    public NostrListBuilder WithImage(string url)
    {
        _image = url ?? throw new ArgumentNullException(nameof(url));
        return this;
    }

    // ----- Public items.

    /// <summary>Adds a public <c>"p"</c> (pubkey) entry.</summary>
    public NostrListBuilder AddPubkey(PublicKey p) => AddPublic(Tag.P(p));

    /// <summary>Adds a public <c>"e"</c> (event id) entry.</summary>
    public NostrListBuilder AddEvent(EventId id, string? relay = null) => AddPublic(Tag.E(id, relay));

    /// <summary>Adds a public <c>"t"</c> (hashtag) entry.</summary>
    public NostrListBuilder AddHashtag(string hashtag) => AddPublic(Tag.T(hashtag));

    /// <summary>Adds a public <c>"word"</c> (muted-word) entry.</summary>
    public NostrListBuilder AddWord(string word) => AddPublic(Tag.Word(word));

    /// <summary>Adds a public <c>"a"</c> (addressable coordinate) entry.</summary>
    public NostrListBuilder AddAddress(int kind, PublicKey author, string identifier, string? relay = null)
        => AddPublic(Tag.A(kind, author, identifier, relay));

    /// <summary>Adds a public <c>"relay"</c> URL entry.</summary>
    public NostrListBuilder AddRelay(string url) => AddPublic(Tag.Relay(url));

    /// <summary>Adds an arbitrary public tag to the list.</summary>
    public NostrListBuilder AddTag(IReadOnlyList<string> tag) => AddPublic(tag);

    // ----- Private items (encrypted in content).

    /// <summary>Adds a private <c>"p"</c> (pubkey) entry, encrypted in content.</summary>
    public NostrListBuilder AddPrivatePubkey(PublicKey p) => AddPrivate(Tag.P(p));

    /// <summary>Adds a private <c>"e"</c> (event id) entry, encrypted in content.</summary>
    public NostrListBuilder AddPrivateEvent(EventId id, string? relay = null) => AddPrivate(Tag.E(id, relay));

    /// <summary>Adds a private <c>"t"</c> (hashtag) entry, encrypted in content.</summary>
    public NostrListBuilder AddPrivateHashtag(string hashtag) => AddPrivate(Tag.T(hashtag));

    /// <summary>Adds a private <c>"word"</c> (muted-word) entry, encrypted in content.</summary>
    public NostrListBuilder AddPrivateWord(string word) => AddPrivate(Tag.Word(word));

    /// <summary>Adds a private <c>"a"</c> (addressable coordinate) entry, encrypted in content.</summary>
    public NostrListBuilder AddPrivateAddress(int kind, PublicKey author, string identifier, string? relay = null)
        => AddPrivate(Tag.A(kind, author, identifier, relay));

    /// <summary>Adds a private <c>"relay"</c> URL entry, encrypted in content.</summary>
    public NostrListBuilder AddPrivateRelay(string url) => AddPrivate(Tag.Relay(url));

    /// <summary>Adds an arbitrary private tag to the list, encrypted in content.</summary>
    public NostrListBuilder AddPrivateTag(IReadOnlyList<string> tag) => AddPrivate(tag);

    /// <summary>
    /// Builds and signs the list event. Private items, if any, are NIP-44
    /// self-encrypted using <paramref name="ownerKey"/>.
    /// </summary>
    /// <param name="ownerKey">The author's private key.</param>
    /// <param name="createdAt">Optional unix-seconds timestamp (defaults to now).</param>
    public NostrEvent Sign(PrivateKey ownerKey, long? createdAt = null)
    {
        ArgumentNullException.ThrowIfNull(ownerKey);

        var tags = new List<IReadOnlyList<string>>();
        if (_identifier is not null)
        {
            tags.Add(Tag.D(_identifier));
        }

        if (_title is not null)
        {
            tags.Add(Tag.Title(_title));
        }

        if (_description is not null)
        {
            tags.Add(Tag.Description(_description));
        }

        if (_image is not null)
        {
            tags.Add(Tag.Image(_image));
        }

        tags.AddRange(_publicItems);

        string content = _privateItems.Count > 0
            ? Nip44.Encrypt(NostrList.SerializeTagArray(_privateItems), ownerKey, ownerKey.PublicKey)
            : string.Empty;

        var unsigned = new UnsignedEvent
        {
            PubKey = ownerKey.PublicKey,
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = _kind,
            Tags = tags,
            Content = content,
        };

        return unsigned.Sign(ownerKey);
    }

    private NostrListBuilder AddPublic(IReadOnlyList<string> tag)
    {
        _publicItems.Add(tag);
        return this;
    }

    private NostrListBuilder AddPrivate(IReadOnlyList<string> tag)
    {
        _privateItems.Add(tag);
        return this;
    }
}
