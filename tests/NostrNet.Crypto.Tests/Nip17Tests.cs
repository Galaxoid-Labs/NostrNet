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

        var giftWrap = Nip17.CreateDirectMessage(Message, alice, bob.PublicKey);

        // Gift wrap should be a valid signed event of kind 1059.
        Assert.Equal(Nip17.GiftWrapKind, giftWrap.Kind);
        Assert.True(giftWrap.Verify());

        // Recipient p-tag points to Bob.
        Assert.Contains(giftWrap.Tags, t => t.Count >= 2 && t[0] == "p" && t[1] == bob.PublicKey.ToHex());

        // Gift wrap pubkey is NOT Alice — it should be ephemeral.
        Assert.NotEqual(alice.PublicKey.ToHex(), giftWrap.PubKey.ToHex());

        // Bob unwraps.
        var unwrapped = Nip17.Unwrap(giftWrap, bob);
        Assert.Equal(Message, unwrapped.Plaintext);
        Assert.Equal(alice.PublicKey, unwrapped.Sender);
        Assert.Contains(unwrapped.Tags, t => t.Count >= 2 && t[0] == "p" && t[1] == bob.PublicKey.ToHex());
    }

    [Fact]
    public void Unwrap_RejectsWrongRecipient()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        using var eve = PrivateKey.Generate();

        var giftWrap = Nip17.CreateDirectMessage("for bob only", alice, bob.PublicKey);
        Assert.ThrowsAny<CryptographicException>(() => { Nip17.Unwrap(giftWrap, eve); });
    }

    [Fact]
    public void Unwrap_RejectsTamperedGiftWrap()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        var giftWrap = Nip17.CreateDirectMessage("hello", alice, bob.PublicKey);

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
        var giftWrap = Nip17.CreateDirectMessage("ping", alice, bob.PublicKey, createdAt: now);

        // Gift wrap should be at or before `now` (jittered backward up to 2 days).
        Assert.InRange(giftWrap.CreatedAt, now - (2 * 24 * 60 * 60), now);
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

        var giftWrap = Nip17.CreateDirectMessage(message, alice, bob.PublicKey);
        var unwrapped = Nip17.Unwrap(giftWrap, bob);
        Assert.Equal(message, unwrapped.Plaintext);
    }
}
