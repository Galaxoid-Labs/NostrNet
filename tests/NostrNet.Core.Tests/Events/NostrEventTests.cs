// SPDX-License-Identifier: MIT
//
// Event-id, signing, and verification tests using vectors from the Galaxoid
// Labs Swift Nostr test suite:
//   https://github.com/Galaxoid-Labs/Nostr/blob/main/Tests/NostrTests/NostrTests.swift

using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Tests.Events;

public class NostrEventTests
{
    // Wire-format event with known-valid id and signature.
    private const string KnownEventJson =
        """
        {"id":"f603166e0fdb6a0329e3998280ecad0e54d89f5f8bc20d1f259a41983aca9dfb","pubkey":"3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d","created_at":1711372078,"kind":1,"tags":[["client","gossip"],["p","fd5989ddfadd9e2af6ceb8b63942a9e31b37367e89917931ede3b2ea76823f10"],["e","7eb018629bcea71512ac83a8b5dab73fa0484c395eafeff797ace4ec463fee7f","wss://nostr.wine/","root"],["e","ab1f4ebf1f75c7bdff65e95bbd068775b5623fedf9be1b0903cbc0b47e1d1c4d","wss://nostr.mom/","reply"]],"content":"Damn, this is frightening.\n\nWhy are early 2000s articles flagged as AI?","sig":"09c197c5159eeac3213fdadec5245501df617a23a5f9b581db22ee822a10f98509302a50335166bd24f672ec19c945e0048bedf25497e53161b80b9e67a1d941"}
        """;

    // Signed event constructed in the Swift suite — verifies our id computation
    // matches reference implementations.
    private const string KnownSigningNsec = "nsec1r7uh0ryrf0n7z3l4qumzevw9q2s57us4wzqrendpavtjn7uvy5rs9szssa";
    private const string KnownSignedEventId = "da036de740ac051db00ac323d4ced88722d005c41fe9d43a90abadc8df3b96e1";
    private const long KnownSignedCreatedAt = 1711384422;

    [Fact]
    public void FromJson_ParsesKnownEvent()
    {
        var ev = NostrEvent.FromJson(KnownEventJson);
        Assert.Equal("f603166e0fdb6a0329e3998280ecad0e54d89f5f8bc20d1f259a41983aca9dfb", ev.Id.ToHex());
        Assert.Equal("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", ev.PubKey.ToHex());
        Assert.Equal(1711372078, ev.CreatedAt);
        Assert.Equal(1, ev.Kind);
        Assert.Equal(4, ev.Tags.Count);
        Assert.Equal("client", ev.Tags[0][0]);
        Assert.Equal("gossip", ev.Tags[0][1]);
        Assert.Contains("frightening", ev.Content);
    }

    [Fact]
    public void Verify_ReturnsTrueForKnownEvent()
    {
        var ev = NostrEvent.FromJson(KnownEventJson);
        Assert.True(ev.Verify(), "Known-valid event must verify.");
    }

    [Fact]
    public void ComputeId_MatchesKnownEventId()
    {
        var ev = NostrEvent.FromJson(KnownEventJson);
        var unsigned = new UnsignedEvent
        {
            PubKey = ev.PubKey,
            CreatedAt = ev.CreatedAt,
            Kind = ev.Kind,
            Tags = ev.Tags,
            Content = ev.Content,
        };

        Assert.Equal(ev.Id, unsigned.ComputeId());
    }

    [Fact]
    public void Sign_ProducesKnownEventId()
    {
        using var key = PrivateKey.FromNsec(KnownSigningNsec);
        var unsigned = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = KnownSignedCreatedAt,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "Hello this is a new event",
        };

        // ComputeId must match the Swift suite's expected value regardless of
        // signing nonce (id is content-derived, not signature-derived).
        Assert.Equal(KnownSignedEventId, unsigned.ComputeId().ToHex());

        // Signing must also produce a self-verifying event.
        var signed = unsigned.Sign(key);
        Assert.Equal(KnownSignedEventId, signed.Id.ToHex());
        Assert.True(signed.Verify());
    }

    [Fact]
    public void Verify_RejectsTamperedContent()
    {
        var ev = NostrEvent.FromJson(KnownEventJson);
        var tampered = new NostrEvent
        {
            Id = ev.Id,
            PubKey = ev.PubKey,
            CreatedAt = ev.CreatedAt,
            Kind = ev.Kind,
            Tags = ev.Tags,
            Content = ev.Content + " (tampered)",
            Sig = ev.Sig,
        };

        Assert.False(tampered.Verify(), "Tampered content must fail verification.");
    }

    [Fact]
    public void Verify_RejectsTamperedSignature()
    {
        var ev = NostrEvent.FromJson(KnownEventJson);
        Span<byte> sigBytes = stackalloc byte[64];
        ev.Sig.AsSpan().CopyTo(sigBytes);
        sigBytes[0] ^= 0x01;

        var tampered = new NostrEvent
        {
            Id = ev.Id,
            PubKey = ev.PubKey,
            CreatedAt = ev.CreatedAt,
            Kind = ev.Kind,
            Tags = ev.Tags,
            Content = ev.Content,
            Sig = new Signature(sigBytes),
        };

        Assert.False(tampered.Verify());
    }

    [Fact]
    public void ToJson_RoundTripsKnownEvent()
    {
        var original = NostrEvent.FromJson(KnownEventJson);
        string json = original.ToJson();
        var roundTripped = NostrEvent.FromJson(json);

        Assert.Equal(original.Id, roundTripped.Id);
        Assert.Equal(original.PubKey, roundTripped.PubKey);
        Assert.Equal(original.CreatedAt, roundTripped.CreatedAt);
        Assert.Equal(original.Kind, roundTripped.Kind);
        Assert.Equal(original.Content, roundTripped.Content);
        Assert.Equal(original.Sig, roundTripped.Sig);
        Assert.True(roundTripped.Verify());
    }

    [Fact]
    public void EventId_NoteBech32_RoundTrips()
    {
        const string Hex = "f603166e0fdb6a0329e3998280ecad0e54d89f5f8bc20d1f259a41983aca9dfb";
        const string Note = "note17cp3vms0md4qx20rnxpgpm9dpe2d386l30pq68e9nfqeswk2nhasgvrk8y";

        var id = EventId.FromHex(Hex);
        Assert.Equal(Note, id.ToNote());

        var fromNote = EventId.FromNote(Note);
        Assert.Equal(Hex, fromNote.ToHex());
        Assert.Equal(id, fromNote);
    }
}
