// SPDX-License-Identifier: MIT
//
// NIP-19 round-trip tests using the Galaxoid Labs Swift Nostr suite's vectors.
// These strings are interoperably verified across implementations.

using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Nip19;

namespace NostrNet.Tests.Nip19;

public class Nip19Tests
{
    // ----- Simple entities (already cross-checked at the Bech32 layer; here
    // we verify the typed wrapper behavior).
    [Fact]
    public void Nip19_Parse_NpubReturnsNpubEntity()
    {
        const string Npub = "npub1fdl779qq4tnsz8e3y8quha37w2hrpme9pcx6z60ql4yyylelk72qplz85a";
        var entity = global::NostrNet.Nip19.Nip19.Parse(Npub);
        var npub = Assert.IsType<NpubEntity>(entity);
        Assert.Equal("4b7fef1400aae7011f3121c1cbf63e72ae30ef250e0da169e0fd48427f3fb794", npub.PubKey.ToHex());
        Assert.Equal(Npub, npub.Encode());
    }

    [Fact]
    public void Nip19_Parse_NoteReturnsNoteEntity()
    {
        const string Note = "note17cp3vms0md4qx20rnxpgpm9dpe2d386l30pq68e9nfqeswk2nhasgvrk8y";
        var entity = global::NostrNet.Nip19.Nip19.Parse(Note);
        var note = Assert.IsType<NoteEntity>(entity);
        Assert.Equal("f603166e0fdb6a0329e3998280ecad0e54d89f5f8bc20d1f259a41983aca9dfb", note.Id.ToHex());
        Assert.Equal(Note, note.Encode());
    }

    [Fact]
    public void Nip19_Parse_NsecIsRejectedWithGuidance()
    {
        const string Nsec = "nsec1r7uh0ryrf0n7z3l4qumzevw9q2s57us4wzqrendpavtjn7uvy5rs9szssa";
        var ex = Assert.Throws<FormatException>(() => global::NostrNet.Nip19.Nip19.Parse(Nsec));
        Assert.Contains("PrivateKey.FromNsec", ex.Message, StringComparison.Ordinal);
    }

    // ----- nprofile vector from the Swift suite.
    [Fact]
    public void Nip19_Nprofile_Decode_MatchesSwiftVector()
    {
        const string Nprofile = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
        var entity = global::NostrNet.Nip19.Nip19.Parse(Nprofile);
        var nprofile = Assert.IsType<NprofileEntity>(entity);
        Assert.Equal("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", nprofile.PubKey.ToHex());
        Assert.Equal(new[] { "wss://r.x.com", "wss://djbas.sadkb.com" }, nprofile.Relays);
    }

    [Fact]
    public void Nip19_Nprofile_Encode_MatchesSwiftVector()
    {
        const string Expected = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p";
        var entity = new NprofileEntity
        {
            PubKey = PublicKey.FromHex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"),
            Relays = new[] { "wss://r.x.com", "wss://djbas.sadkb.com" },
        };
        Assert.Equal(Expected, entity.Encode());
    }

    // ----- nevent vectors from the Swift suite.
    [Fact]
    public void Nip19_Nevent_Decode_MatchesSwiftVector()
    {
        const string Nevent = "nevent1qqsxxr5klnl7uxxhrxl0lgvsf8m27ft8dk00kcuzakfxeyvutd6ja0cprfmhxue69uhhyetvv9ujuam9wd6x2unwvf6xxtnrdaksyg8yvswsamt36tgvpa5v6dgg658umvv4ftquek3xnhdm0fuf0s3xzsa845wv";
        var entity = global::NostrNet.Nip19.Nip19.Parse(Nevent);
        var nevent = Assert.IsType<NeventEntity>(entity);
        Assert.Equal("630e96fcffee18d719beffa19049f6af25676d9efb6382ed926c919c5b752ebf", nevent.Id.ToHex());
        Assert.NotNull(nevent.Author);
        Assert.Equal("e4641d0eed71d2d0c0f68cd3508d50fcdb1954ac1ccda269ddbb7a7897c22614", nevent.Author!.ToHex());
        Assert.Equal(new[] { "wss://relay.westernbtc.com" }, nevent.Relays);
    }

    [Fact]
    public void Nip19_Nevent_Encode_MatchesSwiftVector()
    {
        const string Expected = "nevent1qqsy2vn0t45k92c78n2zfe6ccvqzhpn977cd3h8wnl579zxhw5dvr9qpzpmhxue69uhkyctwv9hxztnrdaksygrl54h466tz4v0re4pyuavvxqptsejl0vxcmnhfl60z3rth2x4m3q04ndyp";
        var entity = new NeventEntity
        {
            Id = EventId.FromHex("45326f5d6962ab1e3cd424e758c3002b8665f7b0d8dcee9fe9e288d7751ac194"),
            Relays = new[] { "wss://banana.com" },
            Author = PublicKey.FromHex("7fa56f5d6962ab1e3cd424e758c3002b8665f7b0d8dcee9fe9e288d7751abb88"),
        };
        Assert.Equal(Expected, entity.Encode());
    }

    // ----- naddr vectors from the Swift suite.
    [Fact]
    public void Nip19_Naddr_Decode_MatchesSwiftVector()
    {
        const string Naddr = "naddr1qqrxyctwv9hxzqfwwaehxw309aex2mrp0yhxummnw3ezuetcv9khqmr99ekhjer0d4skjm3wv4uxzmtsd3jjucm0d5q3vamnwvaz7tmwdaehgu3wvfskuctwvyhxxmmdqgsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8grqsqqqa28a3lkds";
        var entity = global::NostrNet.Nip19.Nip19.Parse(Naddr);
        var naddr = Assert.IsType<NaddrEntity>(entity);
        Assert.Equal("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", naddr.PubKey.ToHex());
        Assert.Equal("banana", naddr.Identifier);
        Assert.Equal(30023, naddr.Kind);
        Assert.Equal(new[] { "wss://relay.nostr.example.mydomain.example.com", "wss://nostr.banana.com" }, naddr.Relays);
    }

    [Fact]
    public void Nip19_Naddr_Encode_MatchesSwiftVector()
    {
        const string Expected = "naddr1qqrxyctwv9hxzqfwwaehxw309aex2mrp0yhxummnw3ezuetcv9khqmr99ekhjer0d4skjm3wv4uxzmtsd3jjucm0d5q3vamnwvaz7tmwdaehgu3wvfskuctwvyhxxmmdqgsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8grqsqqqa28a3lkds";
        var entity = new NaddrEntity
        {
            PubKey = PublicKey.FromHex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"),
            Kind = 30023,
            Identifier = "banana",
            Relays = new[] { "wss://relay.nostr.example.mydomain.example.com", "wss://nostr.banana.com" },
        };
        Assert.Equal(Expected, entity.Encode());
    }

    // ----- NIP-21 URI parsing.
    [Theory]
    [InlineData("nostr:npub1fdl779qq4tnsz8e3y8quha37w2hrpme9pcx6z60ql4yyylelk72qplz85a")]
    [InlineData("nostr:note17cp3vms0md4qx20rnxpgpm9dpe2d386l30pq68e9nfqeswk2nhasgvrk8y")]
    public void Nip21_Parse_AcceptsValidUris(string uri)
    {
        var entity = Nip21.Parse(uri);
        Assert.NotNull(entity);
        Assert.Equal(uri, Nip21.ToUri(entity));
    }

    [Theory]
    [InlineData("npub1fdl779qq4tnsz8e3y8quha37w2hrpme9pcx6z60ql4yyylelk72qplz85a")] // missing scheme
    [InlineData("nostr:")]                                                          // empty
    [InlineData("nostr:notabech32")]
    public void Nip21_TryParse_RejectsInvalid(string uri)
    {
        Assert.False(Nip21.TryParse(uri, out _));
    }

    // ----- Round-trip stability for various entity shapes.
    [Fact]
    public void Nprofile_RoundTrip_StablePreservesData()
    {
        var original = new NprofileEntity
        {
            PubKey = PublicKey.FromHex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"),
            Relays = new[] { "wss://relay.one", "wss://relay.two" },
        };

        string encoded = original.Encode();
        var decoded = (NprofileEntity)global::NostrNet.Nip19.Nip19.Parse(encoded);

        Assert.Equal(original.PubKey, decoded.PubKey);
        Assert.Equal(original.Relays, decoded.Relays);
        Assert.Equal(encoded, decoded.Encode());
    }
}
