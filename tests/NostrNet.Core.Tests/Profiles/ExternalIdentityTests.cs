// SPDX-License-Identifier: MIT

using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Profiles;

namespace NostrNet.Core.Tests.Profiles;

public class ExternalIdentityTests
{
    [Theory]
    [InlineData("github", "semisol", "9721ce4ee4fceb91c9711ca2a6c9a5ab")]
    [InlineData("twitter", "semisol_public", "1619358434134196225")]
    [InlineData("mastodon", "bitcoinhackers.org/@semisol", "109775066355589974")]
    [InlineData("telegram", "1087295469", "nostrdirectory/770")]
    public void Parse_AcceptsSpecExampleTags(string platform, string identity, string proof)
    {
        var tag = new[] { "i", $"{platform}:{identity}", proof };
        var parsed = ExternalIdentity.Parse(tag);

        Assert.Equal(platform, parsed.Platform);
        Assert.Equal(identity, parsed.Identity);
        Assert.Equal(proof, parsed.Proof);
        Assert.Empty(parsed.Extra);
    }

    [Fact]
    public void Parse_PreservesExtraValuesForFutureExtensibility()
    {
        // Spec: "Clients SHOULD process any `i` tags with more than
        // 2 values for future extensibility." Anything past the
        // proof goes into Extra verbatim.
        var tag = new[] { "i", "github:alice", "abc123", "extra1", "extra2" };
        var parsed = ExternalIdentity.Parse(tag);
        Assert.Equal(new[] { "extra1", "extra2" }, parsed.Extra);
    }

    [Fact]
    public void ToTag_RoundTripsThroughParse()
    {
        var original = new ExternalIdentity("github", "alice", "abcdef");
        var rt = ExternalIdentity.Parse(original.ToTag());
        Assert.Equal(original.Platform, rt.Platform);
        Assert.Equal(original.Identity, rt.Identity);
        Assert.Equal(original.Proof, rt.Proof);

        // Extras survive the round trip too.
        var withExtras = new ExternalIdentity("custom", "bob", "p", new[] { "x", "y" });
        var rt2 = ExternalIdentity.Parse(withExtras.ToTag());
        Assert.Equal(new[] { "x", "y" }, rt2.Extra);
    }

    [Fact]
    public void Parse_RejectsWrongShape()
    {
        // Wrong header
        Assert.Throws<ArgumentException>(() => ExternalIdentity.Parse(new[] { "p", "github:alice", "abc" }));
        // Too few values
        Assert.Throws<ArgumentException>(() => ExternalIdentity.Parse(new[] { "i", "github:alice" }));
    }

    [Theory]
    [InlineData("githubalice")] // no colon
    [InlineData("github:")]     // empty identity
    [InlineData(":alice")]      // empty platform
    public void Parse_RejectsMalformedHead(string head)
    {
        Assert.Throws<FormatException>(() => ExternalIdentity.Parse(new[] { "i", head, "abc" }));
    }

    [Fact]
    public void TryParse_ReturnsFalseInsteadOfThrowing()
    {
        Assert.False(ExternalIdentity.TryParse(null, out var n));
        Assert.Null(n);

        Assert.False(ExternalIdentity.TryParse(new[] { "p", "github:alice", "abc" }, out var m));
        Assert.Null(m);

        Assert.True(ExternalIdentity.TryParse(new[] { "i", "github:alice", "abc" }, out var ok));
        Assert.NotNull(ok);
    }

    [Theory]
    [InlineData("github", "alice", "abc", "https://gist.github.com/alice/abc")]
    [InlineData("twitter", "alice", "1619358434134196225", "https://twitter.com/alice/status/1619358434134196225")]
    [InlineData("mastodon", "bitcoinhackers.org/@semisol", "109775066355589974", "https://bitcoinhackers.org/@semisol/109775066355589974")]
    [InlineData("telegram", "1087295469", "nostrdirectory/770", "https://t.me/nostrdirectory/770")]
    public void ProofLocation_BuildsCanonicalUrlPerPlatform(string platform, string identity, string proof, string expected)
    {
        var ext = new ExternalIdentity(platform, identity, proof);
        Assert.Equal(new Uri(expected), ext.ProofLocation());
    }

    [Fact]
    public void ProofLocation_ReturnsNullForUnknownPlatform()
    {
        var ext = new ExternalIdentity("matrix", "@alice:server", "evt-id");
        Assert.Null(ext.ProofLocation());
    }

    [Fact]
    public void VerificationMessage_ProducesPlatformSpecificText()
    {
        using var key = PrivateKey.Generate();
        string npub = key.PublicKey.ToNpub();

        // GitHub — no quotes around the npub per spec
        var gh = ExternalIdentity.VerificationMessage(
            WellKnownIdentityPlatforms.GitHub, key.PublicKey);
        Assert.Equal($"Verifying that I control the following Nostr public key: {npub}", gh);

        // Twitter — distinct wording
        var tw = ExternalIdentity.VerificationMessage(
            WellKnownIdentityPlatforms.Twitter, key.PublicKey);
        Assert.Equal($"Verifying my account on nostr My Public Key: \"{npub}\"", tw);

        // Mastodon + Telegram share the quoted form
        var md = ExternalIdentity.VerificationMessage(
            WellKnownIdentityPlatforms.Mastodon, key.PublicKey);
        Assert.Equal($"Verifying that I control the following Nostr public key: \"{npub}\"", md);

        var tg = ExternalIdentity.VerificationMessage(
            WellKnownIdentityPlatforms.Telegram, key.PublicKey);
        Assert.Equal($"Verifying that I control the following Nostr public key: \"{npub}\"", tg);
    }

    [Fact]
    public void VerificationMessage_ReturnsNullForUnknownPlatform()
    {
        using var key = PrivateKey.Generate();
        Assert.Null(ExternalIdentity.VerificationMessage("matrix", key.PublicKey));
    }

    [Fact]
    public void Profile_FromEvent_PopulatesExternalIdentitiesFromITags()
    {
        // Mirrors the example event from the NIP-39 spec.
        using var key = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = 0,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "i", "github:semisol", "9721ce4ee4fceb91c9711ca2a6c9a5ab" },
                new[] { "i", "twitter:semisol_public", "1619358434134196225" },
                new[] { "i", "mastodon:bitcoinhackers.org/@semisol", "109775066355589974" },
                new[] { "i", "telegram:1087295469", "nostrdirectory/770" },
                new[] { "broken-tag" },  // should be skipped silently
                new[] { "i", "no-colon", "proof" },  // malformed head — skipped
            },
            Content = "{\"name\": \"semisol\"}",
        }.Sign(key);

        var profile = Profile.FromEvent(ev);
        Assert.Equal("semisol", profile.Name);
        Assert.Equal(4, profile.ExternalIdentities.Count);
        Assert.Equal(WellKnownIdentityPlatforms.GitHub, profile.ExternalIdentities[0].Platform);
        Assert.Equal("semisol", profile.ExternalIdentities[0].Identity);
        Assert.Equal(WellKnownIdentityPlatforms.Mastodon, profile.ExternalIdentities[2].Platform);
        Assert.Equal("bitcoinhackers.org/@semisol", profile.ExternalIdentities[2].Identity);
    }

    [Fact]
    public void Profile_FromEvent_EmptyIdentitiesWhenNoITags()
    {
        using var key = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1,
            Kind = 0,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "{\"name\":\"alice\"}",
        }.Sign(key);

        var profile = Profile.FromEvent(ev);
        Assert.Empty(profile.ExternalIdentities);
    }
}
