// SPDX-License-Identifier: MIT
//
// NIP-01 subscription filter.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/01.md (REQ)

using System.Text.Encodings.Web;
using System.Text.Json;
using NostrNet.Events;
using NostrNet.Keys;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Relay;

/// <summary>
/// A NIP-01 subscription filter. Instances are immutable; use the
/// <c>with</c> expression to derive new filters.
/// </summary>
/// <remarks>
/// Each field, when non-null, narrows the matching event set. A filter with
/// all fields null matches every event the relay will return (the relay's
/// global default; usually rejected by relays for cost reasons).
/// </remarks>
public sealed record Filter
{
    /// <summary>Event id hex prefixes to match.</summary>
    public IReadOnlyList<string>? Ids { get; init; }

    /// <summary>Author public-key hex prefixes to match.</summary>
    public IReadOnlyList<string>? Authors { get; init; }

    /// <summary>Event kinds to match.</summary>
    public IReadOnlyList<int>? Kinds { get; init; }

    /// <summary>
    /// Tag filters keyed by tag name (without the <c>#</c> prefix). For example,
    /// to filter on <c>#e</c> tags, use the key <c>"e"</c>.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>>? TagFilters { get; init; }

    /// <summary>Earliest <c>created_at</c> (inclusive), unix seconds.</summary>
    public long? Since { get; init; }

    /// <summary>Latest <c>created_at</c> (inclusive), unix seconds.</summary>
    public long? Until { get; init; }

    /// <summary>Maximum number of stored events to return.</summary>
    public int? Limit { get; init; }

    /// <summary>
    /// NIP-50 full-text search query. When set, the relay matches events
    /// against this string (typically against <see cref="NostrEvent.Content"/>,
    /// though relays MAY include other fields per their own policy).
    /// May embed extension modifiers as space-separated <c>key:value</c>
    /// pairs — well-known examples include <c>include:spam</c> to bypass
    /// the default spam filter and <c>domain:&lt;host&gt;</c> to scope
    /// matches to a NIP-05 host. Relays SHOULD silently ignore unknown
    /// modifiers, so combining several is forward-compatible.
    /// </summary>
    /// <remarks>
    /// Only relays that advertise NIP-50 in their NIP-11 document honor
    /// this field; others ignore it. Pair with <see cref="Kinds"/> and
    /// the standard structured filters to constrain the result set —
    /// most relays cap pure-search queries quite aggressively.
    /// </remarks>
    public string? Search { get; init; }

    /// <summary>
    /// Tests whether <paramref name="ev"/> satisfies this filter's selectors.
    /// </summary>
    /// <remarks>
    /// Matches every populated clause per NIP-01: <see cref="Ids"/> and
    /// <see cref="Authors"/> use hex-prefix matching (case-insensitive);
    /// <see cref="Kinds"/> uses exact equality; <see cref="TagFilters"/>
    /// requires at least one tag row whose name equals the filter key
    /// (without the <c>#</c>) and whose first value is in the supplied list;
    /// <see cref="Since"/> / <see cref="Until"/> are inclusive unix-seconds
    /// bounds. <see cref="Search"/> is matched locally as a
    /// case-insensitive substring against <see cref="NostrEvent.Content"/>
    /// — relays may apply richer semantics; this method gives a
    /// reasonable best-effort approximation for local stores.
    /// <see cref="Limit"/> is NOT applied here — it is a query-level
    /// concern applied after sorting.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="ev"/> is null.</exception>
    public bool Matches(NostrEvent ev)
    {
        ArgumentNullException.ThrowIfNull(ev);

        if (Kinds is { Count: > 0 } kinds && !kinds.Contains(ev.Kind))
        {
            return false;
        }

        if (Since is long since && ev.CreatedAt < since)
        {
            return false;
        }

        if (Until is long until && ev.CreatedAt > until)
        {
            return false;
        }

        if (Ids is { Count: > 0 } ids)
        {
            string idHex = ev.Id.ToHex();
            bool any = false;
            foreach (string prefix in ids)
            {
                if (idHex.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    any = true;
                    break;
                }
            }

            if (!any)
            {
                return false;
            }
        }

        if (Authors is { Count: > 0 } authors)
        {
            string authorHex = ev.PubKey.ToHex();
            bool any = false;
            foreach (string prefix in authors)
            {
                if (authorHex.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    any = true;
                    break;
                }
            }

            if (!any)
            {
                return false;
            }
        }

        if (TagFilters is { Count: > 0 } tagFilters)
        {
            foreach (var (name, values) in tagFilters)
            {
                if (values.Count == 0)
                {
                    continue;
                }

                bool found = false;
                foreach (var row in ev.Tags)
                {
                    if (row.Count >= 2 && string.Equals(row[0], name, StringComparison.Ordinal))
                    {
                        for (int i = 0; i < values.Count; i++)
                        {
                            if (string.Equals(row[1], values[i], StringComparison.Ordinal))
                            {
                                found = true;
                                break;
                            }
                        }

                        if (found)
                        {
                            break;
                        }
                    }
                }

                if (!found)
                {
                    return false;
                }
            }
        }

        if (!string.IsNullOrEmpty(Search) &&
            ev.Content.IndexOf(Search, StringComparison.OrdinalIgnoreCase) < 0)
        {
            return false;
        }

        return true;
    }

    /// <summary>Serializes the filter to its NIP-01 JSON representation.</summary>
    public string ToJson()
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
            WriteTo(writer);
        }

        return SysEncoding.UTF8.GetString(ms.ToArray());
    }

    /// <summary>Writes this filter as a JSON object to <paramref name="writer"/>.</summary>
    public void WriteTo(Utf8JsonWriter writer)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteStartObject();
        WriteStringArray(writer, "ids", Ids);
        WriteStringArray(writer, "authors", Authors);
        WriteIntArray(writer, "kinds", Kinds);

        if (TagFilters is not null)
        {
            foreach (var kvp in TagFilters)
            {
                WriteStringArray(writer, "#" + kvp.Key, kvp.Value);
            }
        }

        if (Since is long since)
        {
            writer.WriteNumber("since", since);
        }

        if (Until is long until)
        {
            writer.WriteNumber("until", until);
        }

        if (Limit is int limit)
        {
            writer.WriteNumber("limit", limit);
        }

        if (!string.IsNullOrEmpty(Search))
        {
            writer.WriteString("search", Search);
        }

        writer.WriteEndObject();
    }

    /// <summary>
    /// Convenience constructor: a NIP-50 search filter for free-form
    /// text. Combine with <c>with</c> expressions to add <see cref="Kinds"/>,
    /// <see cref="Authors"/>, <see cref="Limit"/>, etc.
    /// </summary>
    public static Filter ByText(string query)
    {
        ArgumentException.ThrowIfNullOrEmpty(query);
        return new Filter { Search = query };
    }

    /// <summary>
    /// Convenience constructor: a filter targeting a fixed list of authors.
    /// </summary>
    public static Filter ByAuthors(params PublicKey[] authors)
    {
        ArgumentNullException.ThrowIfNull(authors);
        var hex = new string[authors.Length];
        for (int i = 0; i < authors.Length; i++)
        {
            hex[i] = authors[i].ToHex();
        }

        return new Filter { Authors = hex };
    }

    /// <summary>Convenience constructor: a filter targeting fixed event ids.</summary>
    public static Filter ByIds(params EventId[] ids)
    {
        ArgumentNullException.ThrowIfNull(ids);
        var hex = new string[ids.Length];
        for (int i = 0; i < ids.Length; i++)
        {
            hex[i] = ids[i].ToHex();
        }

        return new Filter { Ids = hex };
    }

    /// <summary>Convenience constructor: a filter targeting fixed kinds.</summary>
    public static Filter ByKinds(params int[] kinds)
    {
        ArgumentNullException.ThrowIfNull(kinds);
        return new Filter { Kinds = kinds };
    }

    private static void WriteStringArray(Utf8JsonWriter writer, string name, IReadOnlyList<string>? values)
    {
        if (values is null)
        {
            return;
        }

        writer.WriteStartArray(name);
        for (int i = 0; i < values.Count; i++)
        {
            writer.WriteStringValue(values[i]);
        }

        writer.WriteEndArray();
    }

    private static void WriteIntArray(Utf8JsonWriter writer, string name, IReadOnlyList<int>? values)
    {
        if (values is null)
        {
            return;
        }

        writer.WriteStartArray(name);
        for (int i = 0; i < values.Count; i++)
        {
            writer.WriteNumberValue(values[i]);
        }

        writer.WriteEndArray();
    }
}
