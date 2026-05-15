// SPDX-License-Identifier: MIT
//
// NIP-39: External Identities.
//
// Reference: https://github.com/nostr-protocol/nips/blob/master/39.md
//
// Adds `i` tags to the kind-0 metadata event, letting a user claim
// usernames on external platforms (github / twitter / mastodon /
// telegram / ...) and pointing to a publicly-fetchable proof of
// ownership.
//
// Wire format (on a kind-0 event):
//
//   ["i", "<platform>:<identity>", "<proof>"]
//
// The first tag value joins platform name and identity with a `:`;
// platform names per spec contain only `a-z`, `0-9`, `._-/` and never
// `:`. The second value points the verifier at a proof: a gist id, a
// tweet id, a mastodon post id, etc. Per spec, additional values
// after the proof MUST be tolerated and preserved for forward
// compatibility.

using NostrNet.Keys;

namespace NostrNet.Profiles;

/// <summary>Well-known NIP-39 platform identifiers (the prefix before <c>:</c> in the first <c>i</c>-tag value).</summary>
public static class WellKnownIdentityPlatforms
{
    /// <summary>GitHub. Identity = username. Proof = gist id at <c>https://gist.github.com/&lt;identity&gt;/&lt;proof&gt;</c>.</summary>
    public const string GitHub = "github";

    /// <summary>Twitter. Identity = handle. Proof = tweet id at <c>https://twitter.com/&lt;identity&gt;/status/&lt;proof&gt;</c>.</summary>
    public const string Twitter = "twitter";

    /// <summary>Mastodon. Identity = <c>&lt;instance&gt;/@&lt;username&gt;</c>. Proof = post id at <c>https://&lt;identity&gt;/&lt;proof&gt;</c>.</summary>
    public const string Mastodon = "mastodon";

    /// <summary>Telegram. Identity = numeric user id. Proof = <c>&lt;ref&gt;/&lt;id&gt;</c> reachable at <c>https://t.me/&lt;proof&gt;</c>.</summary>
    public const string Telegram = "telegram";
}

/// <summary>
/// A NIP-39 external identity claim. Built from one <c>i</c> tag on a
/// kind-0 metadata event.
/// </summary>
/// <param name="Platform">Platform identifier (e.g. <c>"github"</c>). Lowercase per spec; identity-name characters are <c>[a-z0-9._-/]</c>.</param>
/// <param name="Identity">The user's name on the platform.</param>
/// <param name="Proof">Platform-specific proof token (gist id, tweet id, etc.).</param>
/// <param name="Extra">Any extra tag values after <c>proof</c>. Preserved verbatim per spec's forward-compat clause.</param>
public sealed record ExternalIdentity(
    string Platform,
    string Identity,
    string Proof,
    IReadOnlyList<string> Extra)
{
    /// <summary>Convenience constructor without extras.</summary>
    public ExternalIdentity(string platform, string identity, string proof)
        : this(platform, identity, proof, Array.Empty<string>()) { }

    /// <summary>Parses an <c>i</c> tag (the full tag including the <c>"i"</c> header).</summary>
    /// <exception cref="ArgumentException">Tag is not shaped like an NIP-39 <c>i</c> tag.</exception>
    /// <exception cref="FormatException">First value is not in <c>"platform:identity"</c> form.</exception>
    public static ExternalIdentity Parse(IReadOnlyList<string> tag)
    {
        ArgumentNullException.ThrowIfNull(tag);
        if (tag.Count < 3
            || !string.Equals(tag[0], "i", StringComparison.Ordinal))
        {
            throw new ArgumentException("Tag is not a NIP-39 'i' tag (need [\"i\", \"platform:identity\", \"proof\", …]).", nameof(tag));
        }

        string head = tag[1] ?? string.Empty;
        int colon = head.IndexOf(':');
        if (colon <= 0 || colon == head.Length - 1)
        {
            throw new FormatException(
                $"NIP-39 'i' tag's first value must be 'platform:identity'; got '{head}'.");
        }

        string platform = head[..colon];
        string identity = head[(colon + 1)..];
        string proof = tag[2] ?? string.Empty;
        IReadOnlyList<string> extra = tag.Count > 3
            ? tag.Skip(3).ToArray()
            : Array.Empty<string>();

        return new ExternalIdentity(platform, identity, proof, extra);
    }

    /// <summary>Try-parse variant. Returns <c>false</c> for any malformed input without throwing.</summary>
    public static bool TryParse(IReadOnlyList<string>? tag, out ExternalIdentity? identity)
    {
        identity = null;
        if (tag is null) return false;
        try
        {
            identity = Parse(tag);
            return true;
        }
        catch (ArgumentException) { return false; }
        catch (FormatException) { return false; }
    }

    /// <summary>Serializes back to an <c>i</c> tag (including the leading <c>"i"</c>).</summary>
    public IReadOnlyList<string> ToTag()
    {
        var tag = new List<string>(3 + Extra.Count)
        {
            "i",
            Platform + ":" + Identity,
            Proof,
        };

        foreach (var extra in Extra) tag.Add(extra);
        return tag;
    }

    /// <summary>
    /// The canonical URL where this proof should be readable, when
    /// the platform is one of the well-known ones in
    /// <see cref="WellKnownIdentityPlatforms"/>. Returns <c>null</c>
    /// for unknown platforms — callers building generic verifiers
    /// shouldn't assume a location.
    /// </summary>
    public Uri? ProofLocation() => Platform switch
    {
        WellKnownIdentityPlatforms.GitHub
            => new Uri($"https://gist.github.com/{Identity}/{Proof}"),
        WellKnownIdentityPlatforms.Twitter
            => new Uri($"https://twitter.com/{Identity}/status/{Proof}"),
        WellKnownIdentityPlatforms.Mastodon
            => new Uri($"https://{Identity}/{Proof}"),
        WellKnownIdentityPlatforms.Telegram
            => new Uri($"https://t.me/{Proof}"),
        _ => null,
    };

    /// <summary>
    /// The verification-message text the user must publish on the
    /// platform to prove ownership of this Nostr pubkey. Returns
    /// <c>null</c> for platforms without a well-known template.
    /// </summary>
    /// <remarks>
    /// Per NIP-39 the message embeds the user's npub. Apps showing
    /// "Paste this exact text on GitHub" should call this and render
    /// the result so the wording matches what verifiers expect.
    /// </remarks>
    public static string? VerificationMessage(string platform, PublicKey nostrPubkey)
    {
        ArgumentException.ThrowIfNullOrEmpty(platform);
        ArgumentNullException.ThrowIfNull(nostrPubkey);

        string npub = nostrPubkey.ToNpub();
        return platform switch
        {
            // GitHub gist body — no quotes around the npub per spec.
            WellKnownIdentityPlatforms.GitHub
                => $"Verifying that I control the following Nostr public key: {npub}",

            // Twitter — distinct wording and quoted npub.
            WellKnownIdentityPlatforms.Twitter
                => $"Verifying my account on nostr My Public Key: \"{npub}\"",

            // Mastodon / Telegram share the "Verifying that I control … \"npub…\"" form.
            WellKnownIdentityPlatforms.Mastodon
                or WellKnownIdentityPlatforms.Telegram
                => $"Verifying that I control the following Nostr public key: \"{npub}\"",

            _ => null,
        };
    }
}
