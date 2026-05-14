// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using NostrNet.Crypto;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Marmot;
using NostrNet.Marmot.Events;

namespace NostrNet.Marmot.Tests.Events;

public class WelcomeEventTests
{
    private static byte[] RandomBytes(int length, int seed)
    {
        byte[] b = new byte[length];
        new Random(seed).NextBytes(b);
        return b;
    }

    [Fact]
    public void Build_AndUnwrap_RoundTrip()
    {
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();

        byte[] welcomeBytes = RandomBytes(220, 1);
        string keyPackageId = new string('a', 64);
        var relays = new[] { "wss://relay.example.com", "wss://nos.lol" };

        var giftWrap = WelcomeEvent.Build(
            mlsWelcomeBytes: welcomeBytes,
            keyPackageEventId: keyPackageId,
            senderKey: sender,
            recipientPubkey: recipient.PublicKey,
            recommendedRelays: relays);

        Assert.Equal(1059, giftWrap.Kind);
        Assert.True(giftWrap.Verify());
        // Gift wrap is signed by an ephemeral key, NOT by the sender.
        Assert.NotEqual(sender.PublicKey, giftWrap.PubKey);
        // Recipient is named in a p-tag.
        Assert.Equal(recipient.PublicKey.ToHex(), giftWrap.Tags.FirstValue("p"));

        var unwrapped = WelcomeEvent.Unwrap(giftWrap, recipient);
        Assert.Equal(sender.PublicKey, unwrapped.Sender);
        Assert.Equal(welcomeBytes, unwrapped.MlsWelcomeBytes);
        Assert.Equal(keyPackageId, unwrapped.KeyPackageEventId);
        Assert.Equal(relays, unwrapped.RecommendedRelays);
    }

    [Fact]
    public void Build_UsesFreshEphemeralKeyPerCall()
    {
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();
        byte[] welcomeBytes = RandomBytes(64, 1);
        string kpId = new string('b', 64);

        var ev1 = WelcomeEvent.Build(welcomeBytes, kpId, sender, recipient.PublicKey, Array.Empty<string>());
        var ev2 = WelcomeEvent.Build(welcomeBytes, kpId, sender, recipient.PublicKey, Array.Empty<string>());

        Assert.NotEqual(ev1.PubKey, ev2.PubKey);
        Assert.NotEqual(ev1.Content, ev2.Content);
    }

    [Fact]
    public void Build_OmitsRelaysTag_WhenEmpty()
    {
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();

        var giftWrap = WelcomeEvent.Build(
            RandomBytes(50, 1),
            new string('c', 64),
            sender,
            recipient.PublicKey,
            Array.Empty<string>());

        var unwrapped = WelcomeEvent.Unwrap(giftWrap, recipient);
        Assert.Empty(unwrapped.RecommendedRelays);
    }

    [Fact]
    public void Unwrap_FailsForWrongRecipient()
    {
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();
        using var stranger = PrivateKey.Generate();

        var giftWrap = WelcomeEvent.Build(
            RandomBytes(64, 1),
            new string('d', 64),
            sender,
            recipient.PublicKey,
            new[] { "wss://r.example" });

        Assert.Throws<CryptographicException>(() => WelcomeEvent.Unwrap(giftWrap, stranger));
    }

    [Fact]
    public void TryUnwrap_ReturnsFalseOnWrongRecipient()
    {
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();
        using var stranger = PrivateKey.Generate();

        var giftWrap = WelcomeEvent.Build(
            RandomBytes(64, 1),
            new string('e', 64),
            sender,
            recipient.PublicKey,
            Array.Empty<string>());

        Assert.False(WelcomeEvent.TryUnwrap(giftWrap, stranger, out var u));
        Assert.Null(u);

        Assert.True(WelcomeEvent.TryUnwrap(giftWrap, recipient, out u));
        Assert.NotNull(u);
        Assert.Equal(sender.PublicKey, u.Sender);
    }

    [Fact]
    public void Unwrap_RejectsWrongKind()
    {
        using var key = PrivateKey.Generate();
        var note = new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "",
        }.Sign(key);

        Assert.Throws<ArgumentException>(() => WelcomeEvent.Unwrap(note, key));
    }

    [Fact]
    public void Unwrap_RejectsTamperedInnerSealKind()
    {
        // Forge a gift wrap whose decrypted "seal" is a kind-1 note instead of kind-13.
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();
        using var ephemeral = PrivateKey.Generate();

        // Build a kind-1 "seal" instead of kind-13 and re-wrap it manually.
        var fakeSeal = new UnsignedEvent
        {
            PubKey = sender.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,                                    // WRONG
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = Nip44.Encrypt("{}", sender, recipient.PublicKey),
        }.Sign(sender);

        string encryptedSeal = Nip44.Encrypt(fakeSeal.ToJson(), ephemeral, recipient.PublicKey);
        var giftWrap = new UnsignedEvent
        {
            PubKey = ephemeral.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1059,
            Tags = new IReadOnlyList<string>[] { new[] { "p", recipient.PublicKey.ToHex() } },
            Content = encryptedSeal,
        }.Sign(ephemeral);

        Assert.Throws<CryptographicException>(() => WelcomeEvent.Unwrap(giftWrap, recipient));
    }

    [Fact]
    public void Unwrap_RejectsRumorPubkeyMismatch()
    {
        // Seal signed by Alice, but rumor.pubkey claims Mallory.
        using var alice = PrivateKey.Generate();
        using var mallory = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();
        using var ephemeral = PrivateKey.Generate();

        string rumor = "{\"pubkey\":\"" + mallory.PublicKey.ToHex()
            + "\",\"created_at\":1700000000,\"kind\":444,\"tags\":[[\"e\",\""
            + new string('a', 64)
            + "\"],[\"encoding\",\"base64\"]],\"content\":\""
            + Convert.ToBase64String(new byte[] { 1, 2, 3 })
            + "\"}";

        var seal = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 13,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = Nip44.Encrypt(rumor, alice, recipient.PublicKey),
        }.Sign(alice);

        var giftWrap = new UnsignedEvent
        {
            PubKey = ephemeral.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1059,
            Tags = new IReadOnlyList<string>[] { new[] { "p", recipient.PublicKey.ToHex() } },
            Content = Nip44.Encrypt(seal.ToJson(), ephemeral, recipient.PublicKey),
        }.Sign(ephemeral);

        Assert.Throws<CryptographicException>(() => WelcomeEvent.Unwrap(giftWrap, recipient));
    }

    [Fact]
    public void Unwrap_RejectsRumorMissingKeyPackageETag()
    {
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();
        using var ephemeral = PrivateKey.Generate();

        string rumor = "{\"pubkey\":\"" + sender.PublicKey.ToHex()
            + "\",\"created_at\":1700000000,\"kind\":444,\"tags\":[[\"encoding\",\"base64\"]],\"content\":\""
            + Convert.ToBase64String(new byte[] { 1, 2, 3 })
            + "\"}";

        var seal = new UnsignedEvent
        {
            PubKey = sender.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 13,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = Nip44.Encrypt(rumor, sender, recipient.PublicKey),
        }.Sign(sender);

        var giftWrap = new UnsignedEvent
        {
            PubKey = ephemeral.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1059,
            Tags = new IReadOnlyList<string>[] { new[] { "p", recipient.PublicKey.ToHex() } },
            Content = Nip44.Encrypt(seal.ToJson(), ephemeral, recipient.PublicKey),
        }.Sign(ephemeral);

        Assert.Throws<CryptographicException>(() => WelcomeEvent.Unwrap(giftWrap, recipient));
    }

    [Fact]
    public void Build_HonorsCustomCreatedAt()
    {
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();

        long fixedTs = 1_700_000_000L;
        var giftWrap = WelcomeEvent.Build(
            RandomBytes(50, 1),
            new string('f', 64),
            sender,
            recipient.PublicKey,
            Array.Empty<string>(),
            createdAt: fixedTs);

        // Both seal and wrap are jittered BACKWARD up to 2 days, so
        // outer created_at is somewhere in [fixedTs - 2d, fixedTs].
        long minTs = fixedTs - 2 * 24 * 60 * 60;
        Assert.InRange(giftWrap.CreatedAt, minTs, fixedTs);

        // And the inner rumor's created_at survives intact through unwrap.
        var u = WelcomeEvent.Unwrap(giftWrap, recipient);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(fixedTs), u.RumorCreatedAt);
    }
}
