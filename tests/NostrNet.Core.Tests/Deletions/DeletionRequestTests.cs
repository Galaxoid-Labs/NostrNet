// SPDX-License-Identifier: MIT
//
// Tests for NIP-09 deletion request round-trips and targeting rules.

using NostrNet.Deletions;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Tests.Deletions;

public class DeletionRequestTests
{
    private static EventId RandomId(int seed)
    {
        byte[] b = new byte[32];
        new Random(seed).NextBytes(b);
        return new EventId(b);
    }

    [Fact]
    public void Build_AndParse_PreservesTags()
    {
        using var key = PrivateKey.Generate();
        using var someoneElse = PrivateKey.Generate();
        var id1 = RandomId(1);
        var id2 = RandomId(2);

        var ev = DeletionRequest.Create()
            .AddEvent(id1)
            .AddEvent(id2)
            .AddAddressableEvent(kind: 30023, author: someoneElse.PublicKey, identifier: "my-article")
            .AddKind(1)
            .AddKind(30023)
            .WithReason("posted by accident")
            .Sign(key);

        Assert.Equal(Nip09Kinds.DeletionRequest, ev.Kind);
        Assert.True(ev.Verify());

        var req = DeletionRequest.FromEvent(ev);
        Assert.Equal(key.PublicKey, req.Requester);
        Assert.Equal(2, req.EventIds.Count);
        Assert.Equal(id1, req.EventIds[0]);
        Assert.Equal(id2, req.EventIds[1]);
        Assert.Single(req.AddressableEvents);
        Assert.Equal(30023, req.AddressableEvents[0].Kind);
        Assert.Equal(someoneElse.PublicKey, req.AddressableEvents[0].Author);
        Assert.Equal("my-article", req.AddressableEvents[0].Identifier);
        Assert.Equal(new[] { 1, 30023 }, req.Kinds);
        Assert.Equal("posted by accident", req.Reason);
    }

    [Fact]
    public void Targets_NonReplaceable_MatchesByEventId()
    {
        using var alice = PrivateKey.Generate();

        // Alice posts something:
        var note = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "oops",
        }.Sign(alice);

        // Alice issues a deletion request referencing it:
        var del = DeletionRequest.Create().AddEvent(note.Id).Sign(alice);
        var req = DeletionRequest.FromEvent(del);

        Assert.True(req.Targets(note));
    }

    [Fact]
    public void Targets_RejectsDifferentAuthor()
    {
        // The critical security check — Alice can't delete Bob's events.
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        var bobsNote = new UnsignedEvent
        {
            PubKey = bob.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "bob's content",
        }.Sign(bob);

        // Alice references Bob's event id in her deletion. The request
        // is well-formed but MUST NOT target Bob's event.
        var aliceDel = DeletionRequest.Create().AddEvent(bobsNote.Id).Sign(alice);
        var req = DeletionRequest.FromEvent(aliceDel);

        Assert.False(req.Targets(bobsNote));
    }

    [Fact]
    public void Targets_Addressable_MatchesByCoordinates()
    {
        using var alice = PrivateKey.Generate();

        // Alice posts a NIP-23 long-form article (kind 30023, parameterized-replaceable).
        var article = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 30023,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "d", "my-article" },
            },
            Content = "# Hello",
        }.Sign(alice);

        // She wants to take it down with an "a"-tag deletion:
        var del = DeletionRequest.Create()
            .AddAddressableEvent(kind: 30023, author: alice.PublicKey, identifier: "my-article")
            .Sign(alice);
        var req = DeletionRequest.FromEvent(del);

        Assert.True(req.Targets(article));
    }

    [Fact]
    public void Targets_Addressable_DoesNotMatchOnDifferentDTag()
    {
        using var alice = PrivateKey.Generate();
        var article = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 30023,
            Tags = new IReadOnlyList<string>[] { new[] { "d", "article-a" } },
            Content = "a",
        }.Sign(alice);

        // Deletion request points at a different d-tag identifier.
        var del = DeletionRequest.Create()
            .AddAddressableEvent(30023, alice.PublicKey, "article-b")
            .Sign(alice);
        var req = DeletionRequest.FromEvent(del);

        Assert.False(req.Targets(article));
    }

    [Fact]
    public void AddressableEventCoordinates_ParsesTagValue()
    {
        using var key = PrivateKey.Generate();
        string value = $"30023:{key.PublicKey.ToHex()}:my-article";
        Assert.True(AddressableEventCoordinates.TryParse(value, out var coords));
        Assert.NotNull(coords);
        Assert.Equal(30023, coords.Kind);
        Assert.Equal(key.PublicKey, coords.Author);
        Assert.Equal("my-article", coords.Identifier);
        Assert.Equal(value, coords.ToTagValue());

        Assert.False(AddressableEventCoordinates.TryParse(null, out _));
        Assert.False(AddressableEventCoordinates.TryParse("not-enough:parts", out _));
        Assert.False(AddressableEventCoordinates.TryParse("kind:bad-pubkey:slot", out _));
        Assert.False(AddressableEventCoordinates.TryParse($"notakind:{key.PublicKey.ToHex()}:slot", out _));
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
            Content = "not a deletion",
        }.Sign(key);

        Assert.Throws<ArgumentException>(() => DeletionRequest.FromEvent(ev));
        Assert.False(DeletionRequest.TryFromEvent(ev, out _));
    }
}
