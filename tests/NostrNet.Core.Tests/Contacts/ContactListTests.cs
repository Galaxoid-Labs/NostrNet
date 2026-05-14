// SPDX-License-Identifier: MIT
//
// Tests for NIP-02 contact list round-trips.

using NostrNet.Contacts;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Tests.Contacts;

public class ContactListTests
{
    [Fact]
    public void Build_AndParse_PreservesAllEntries()
    {
        using var key = PrivateKey.Generate();
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        using var carolKey = PrivateKey.Generate();

        var ev = ContactList.Create()
            .AddContact(aliceKey.PublicKey)                                     // bare pubkey
            .AddContact(bobKey.PublicKey, recommendedRelay: "wss://relay.bob")  // pubkey + relay
            .AddContact(carolKey.PublicKey, recommendedRelay: "wss://r.carol", petname: "carol")
            .Sign(key);

        Assert.Equal(Nip02Kinds.ContactList, ev.Kind);
        Assert.True(ev.Verify());
        Assert.Equal(string.Empty, ev.Content);

        var list = ContactList.FromEvent(ev);
        Assert.Equal(key.PublicKey, list.Owner);
        Assert.Equal(3, list.Contacts.Count);

        Assert.Equal(aliceKey.PublicKey, list.Contacts[0].PubKey);
        Assert.Null(list.Contacts[0].RecommendedRelay);
        Assert.Null(list.Contacts[0].Petname);

        Assert.Equal(bobKey.PublicKey, list.Contacts[1].PubKey);
        Assert.Equal("wss://relay.bob", list.Contacts[1].RecommendedRelay);
        Assert.Null(list.Contacts[1].Petname);

        Assert.Equal(carolKey.PublicKey, list.Contacts[2].PubKey);
        Assert.Equal("wss://r.carol", list.Contacts[2].RecommendedRelay);
        Assert.Equal("carol", list.Contacts[2].Petname);
    }

    [Fact]
    public void Follows_FindsPresentPubkey()
    {
        using var key = PrivateKey.Generate();
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        using var stranger = PrivateKey.Generate();

        var ev = ContactList.Create()
            .AddContact(alice.PublicKey)
            .AddContact(bob.PublicKey)
            .Sign(key);

        var list = ContactList.FromEvent(ev);
        Assert.True(list.Follows(alice.PublicKey));
        Assert.True(list.Follows(bob.PublicKey));
        Assert.False(list.Follows(stranger.PublicKey));
    }

    [Fact]
    public void RawContent_RoundTripsAsPassthrough()
    {
        // Legacy / non-standard payload should survive verbatim.
        using var key = PrivateKey.Generate();
        const string LegacyRelaysJson = "{\"wss://relay.example.com\":{\"read\":true,\"write\":true}}";

        var ev = ContactList.Create()
            .WithRawContent(LegacyRelaysJson)
            .Sign(key);

        var list = ContactList.FromEvent(ev);
        Assert.Equal(LegacyRelaysJson, list.RawContent);
    }

    [Fact]
    public void FromEvent_SkipsMalformedPTags()
    {
        // Build an event by hand with one valid + several malformed p tags.
        using var key = PrivateKey.Generate();
        using var goodKey = PrivateKey.Generate();

        var tags = new IReadOnlyList<string>[]
        {
            new[] { "p" },                                  // no value
            new[] { "p", "" },                               // empty value
            new[] { "p", "not-hex" },                        // bad hex
            new[] { "p", new string('z', 64) },              // wrong-length-valid-hex chars
            new[] { "p", goodKey.PublicKey.ToHex() },        // good
        };

        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = Nip02Kinds.ContactList,
            Tags = tags,
            Content = string.Empty,
        }.Sign(key);

        var list = ContactList.FromEvent(ev);
        Assert.Single(list.Contacts);
        Assert.Equal(goodKey.PublicKey, list.Contacts[0].PubKey);
    }

    [Fact]
    public void FromEvent_RejectsWrongKind()
    {
        using var key = PrivateKey.Generate();
        var ev = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "not a contact list",
        }.Sign(key);

        Assert.Throws<ArgumentException>(() => ContactList.FromEvent(ev));
        Assert.False(ContactList.TryFromEvent(ev, out _));
        Assert.False(ContactList.TryFromEvent(null, out _));
    }
}
