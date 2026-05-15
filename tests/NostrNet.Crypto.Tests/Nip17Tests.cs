// SPDX-License-Identifier: MIT
//
// Round-trip tests for NIP-17 / NIP-59 gift-wrapped direct messages.

using System.Security.Cryptography;
using NostrNet.Crypto;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Tests.Crypto;

public class Nip17Tests
{
    [Fact]
    public void RoundTrip_AliceToBob_RecoversPlaintext()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        const string Message = "hey bob, can you read this?";

        var dm = Nip17.CreateDirectMessage(Message, alice, bob.PublicKey);

        // Recipient-addressed wrap should be a valid signed event of kind 1059.
        Assert.Equal(Nip17.GiftWrapKind, dm.ToRecipient.Kind);
        Assert.True(dm.ToRecipient.Verify());

        // Outer p-tag points to Bob.
        Assert.Contains(dm.ToRecipient.Tags, t => t.Count >= 2 && t[0] == "p" && t[1] == bob.PublicKey.ToHex());

        // Outer pubkey is ephemeral, not Alice's.
        Assert.NotEqual(alice.PublicKey.ToHex(), dm.ToRecipient.PubKey.ToHex());

        // Bob unwraps the recipient copy.
        var unwrapped = Nip17.Unwrap(dm.ToRecipient, bob);
        Assert.Equal(Message, unwrapped.Plaintext);
        Assert.Equal(alice.PublicKey, unwrapped.Sender);
        Assert.Contains(unwrapped.Tags, t => t.Count >= 2 && t[0] == "p" && t[1] == bob.PublicKey.ToHex());
    }

    [Fact]
    public void CreateDirectMessage_ProducesSelfAddressedWrapWithMatchingInnerRumor()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        const string Message = "history should follow me to my other devices";

        var dm = Nip17.CreateDirectMessage(Message, alice, bob.PublicKey);

        // Self-wrap is a separate kind-1059 event addressed to Alice.
        Assert.Equal(Nip17.GiftWrapKind, dm.ToSelf.Kind);
        Assert.True(dm.ToSelf.Verify());
        Assert.Contains(dm.ToSelf.Tags, t => t.Count >= 2 && t[0] == "p" && t[1] == alice.PublicKey.ToHex());

        // Two distinct outer wraps (different ephemeral keys, different
        // outer-encryption keys).
        Assert.NotEqual(dm.ToRecipient.Id.ToHex(), dm.ToSelf.Id.ToHex());

        // But the inner rumor is the same — same plaintext, same sender,
        // same created_at, same tags.
        var fromBob = Nip17.Unwrap(dm.ToRecipient, bob);
        var fromAlice = Nip17.Unwrap(dm.ToSelf, alice);
        Assert.Equal(fromBob.Plaintext, fromAlice.Plaintext);
        Assert.Equal(fromBob.Sender, fromAlice.Sender);
        Assert.Equal(fromBob.CreatedAt, fromAlice.CreatedAt);

        // Inner p-tag on both unwraps points to the actual recipient (Bob),
        // not Alice — distinguishing the rumor from a true inbound DM.
        Assert.Contains(fromAlice.Tags, t => t.Count >= 2 && t[0] == "p" && t[1] == bob.PublicKey.ToHex());
    }

    [Fact]
    public void Unwrap_RejectsWrongRecipient()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        using var eve = PrivateKey.Generate();

        var dm = Nip17.CreateDirectMessage("for bob only", alice, bob.PublicKey);
        Assert.ThrowsAny<CryptographicException>(() => { Nip17.Unwrap(dm.ToRecipient, eve); });
    }

    [Fact]
    public void Unwrap_RejectsTamperedGiftWrap()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        var dm = Nip17.CreateDirectMessage("hello", alice, bob.PublicKey);
        var giftWrap = dm.ToRecipient;

        // Build a new event with a tampered content; signature won't verify so
        // Unwrap should fail (either at signature or decrypt time).
        var tamperedContent = giftWrap.Content[..^1] + (giftWrap.Content[^1] == 'A' ? 'B' : 'A');
        var tampered = new NostrEvent
        {
            Id = giftWrap.Id,
            PubKey = giftWrap.PubKey,
            CreatedAt = giftWrap.CreatedAt,
            Kind = giftWrap.Kind,
            Tags = giftWrap.Tags,
            Content = tamperedContent,
            Sig = giftWrap.Sig,
        };

        Assert.ThrowsAny<Exception>(() => { Nip17.Unwrap(tampered, bob); });
    }

    [Fact]
    public void Unwrap_RejectsWrongKind()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        var notAGiftWrap = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "just a regular note",
        }.Sign(alice);

        Assert.Throws<ArgumentException>(() => { Nip17.Unwrap(notAGiftWrap, bob); });
    }

    [Fact]
    public void CreateDirectMessage_GiftWrapTimestampIsJitteredBackward()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var dm = Nip17.CreateDirectMessage("ping", alice, bob.PublicKey, createdAt: now);

        // Both wraps should be at or before `now` (jittered backward up to 2 days).
        Assert.InRange(dm.ToRecipient.CreatedAt, now - (2 * 24 * 60 * 60), now);
        Assert.InRange(dm.ToSelf.CreatedAt, now - (2 * 24 * 60 * 60), now);
    }

    [Fact]
    public void CreateDirectMessage_WithReplyTo_AddsNip10ReplyMarker()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        var parent = Nip17.CreateDirectMessage("first", alice, bob.PublicKey);
        var parentRumor = Nip17.Unwrap(parent.ToRecipient, bob);

        var dm = Nip17.CreateDirectMessage(
            "yes!",
            senderPrivateKey: bob,
            recipientPublicKey: alice.PublicKey,
            replyTo: parentRumor.RumorId);

        var unwrapped = Nip17.Unwrap(dm.ToRecipient, alice);

        // Reply tag should be present with NIP-10 "reply" marker pointing at the parent rumor id.
        var replyTag = unwrapped.Tags.FirstOrDefault(t =>
            t.Count >= 4 && t[0] == "e" && t[3] == "reply");
        Assert.NotNull(replyTag);
        Assert.Equal(parentRumor.RumorId.ToHex(), replyTag[1]);
        Assert.Equal(string.Empty, replyTag[2]);

        // No "root" tag emitted when only replyTo is supplied.
        Assert.DoesNotContain(unwrapped.Tags, t => t.Count >= 4 && t[0] == "e" && t[3] == "root");
    }

    [Fact]
    public void CreateDirectMessage_WithReplyAndRoot_EmitsBothMarkers()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        var rootDm = Nip17.CreateDirectMessage("the root", alice, bob.PublicKey);
        var root = Nip17.Unwrap(rootDm.ToRecipient, bob);

        // Simulate a parent that's one level down from root (we don't actually
        // need to construct one — just use a different EventId).
        using var someOther = PrivateKey.Generate();
        var fakeParent = Nip17.Unwrap(
            Nip17.CreateDirectMessage("middle", someOther, bob.PublicKey).ToRecipient, bob);

        var deep = Nip17.CreateDirectMessage(
            "deep reply",
            senderPrivateKey: bob,
            recipientPublicKey: alice.PublicKey,
            replyTo: fakeParent.RumorId,
            replyRoot: root.RumorId);

        var unwrapped = Nip17.Unwrap(deep.ToRecipient, alice);

        var rootTag = unwrapped.Tags.FirstOrDefault(t =>
            t.Count >= 4 && t[0] == "e" && t[3] == "root");
        var replyTag = unwrapped.Tags.FirstOrDefault(t =>
            t.Count >= 4 && t[0] == "e" && t[3] == "reply");

        Assert.NotNull(rootTag);
        Assert.NotNull(replyTag);
        Assert.Equal(root.RumorId.ToHex(), rootTag[1]);
        Assert.Equal(fakeParent.RumorId.ToHex(), replyTag[1]);
    }

    [Fact]
    public void CreateReaction_ProducesKind7RumorWithEAndPTags()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        var dm = Nip17.CreateDirectMessage("a note worth reacting to", alice, bob.PublicKey);
        var asBob = Nip17.Unwrap(dm.ToRecipient, bob);

        var reactionDm = Nip17.CreateReaction(
            reaction: "👍",
            targetRumorId: asBob.RumorId,
            targetAuthor: alice.PublicKey,
            senderPrivateKey: bob);

        var asAlice = Nip17.Unwrap(reactionDm.ToRecipient, alice);

        Assert.Equal(Nip17.ReactionRumorKind, asAlice.Kind);
        Assert.Equal("👍", asAlice.Plaintext);
        Assert.Contains(asAlice.Tags, t => t.Count >= 2 && t[0] == "e" && t[1] == asBob.RumorId.ToHex());
        Assert.Contains(asAlice.Tags, t => t.Count >= 2 && t[0] == "p" && t[1] == alice.PublicKey.ToHex());
        Assert.Equal(bob.PublicKey, asAlice.Sender);
    }

    [Fact]
    public void Unwrap_RejectsRumorOutsideDmFamily()
    {
        // Wrap a kind-444 (Marmot Welcome) rumor and confirm Nip17.Unwrap
        // refuses to surface it — this is what keeps stray Marmot welcomes
        // out of SubscribeDirectMessagesAsync.
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        var dm = Nip17.WrapRumor(
            kind: 444,
            content: "pretend-welcome",
            tags: Array.Empty<IReadOnlyList<string>>(),
            senderPrivateKey: alice,
            recipientPublicKey: bob.PublicKey);

        var ex = Assert.Throws<CryptographicException>(() => Nip17.Unwrap(dm.ToRecipient, bob));
        Assert.Contains("444", ex.Message);
    }

    [Fact]
    public void WrapRumor_PreservesArbitraryKindAndTags()
    {
        // Kind 15 (file message) is in the DM family and should roundtrip cleanly.
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        var dm = Nip17.WrapRumor(
            kind: Nip17.FileRumorKind,
            content: "https://example.com/photo.jpg",
            tags: new IReadOnlyList<string>[]
            {
                new[] { "p", bob.PublicKey.ToHex() },
                new[] { "file-type", "image/jpeg" },
            },
            senderPrivateKey: alice,
            recipientPublicKey: bob.PublicKey);

        var unwrapped = Nip17.Unwrap(dm.ToRecipient, bob);
        Assert.Equal(Nip17.FileRumorKind, unwrapped.Kind);
        Assert.Equal("https://example.com/photo.jpg", unwrapped.Plaintext);
        Assert.Contains(unwrapped.Tags, t => t.Count >= 2 && t[0] == "file-type" && t[1] == "image/jpeg");
    }

    [Fact]
    public void RoundTrip_LongMessage()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        // ~2KB message exercises non-trivial padding sizes.
        string message = string.Create(2000, alice.PublicKey, (chars, _) =>
        {
            for (int i = 0; i < chars.Length; i++)
            {
                chars[i] = (char)('a' + (i % 26));
            }
        });

        var dm = Nip17.CreateDirectMessage(message, alice, bob.PublicKey);
        var unwrapped = Nip17.Unwrap(dm.ToRecipient, bob);
        Assert.Equal(message, unwrapped.Plaintext);
    }
}
