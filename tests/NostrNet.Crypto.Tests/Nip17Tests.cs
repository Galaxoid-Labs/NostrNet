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
