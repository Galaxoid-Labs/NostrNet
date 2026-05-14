// SPDX-License-Identifier: MIT
//
// Unit tests for the NIP-59 gift-wrap module. These exercise the public
// API at the abstraction it's meant for — sealing/unwrapping arbitrary
// rumors of any kind — independent of NIP-17 chat or Marmot Welcomes.

using System.Security.Cryptography;
using System.Text.Json;
using NostrNet.Crypto;
using NostrNet.Events;
using NostrNet.Keys;

namespace NostrNet.Tests.Crypto;

public class Nip59Tests
{
    private const int ArbitraryRumorKind = 9999;

    private static Rumor MakeRumor(string content = "hello, world") => new(
        Kind: ArbitraryRumorKind,
        CreatedAt: 1_700_000_000L,
        Tags: new IReadOnlyList<string>[]
        {
            new[] { "subject", "test" },
            new[] { "t", "nip59" },
        },
        Content: content);

    [Fact]
    public void Wrap_AndUnwrap_RoundTrip()
    {
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();

        var rumor = MakeRumor();
        var wrap = Nip59.Wrap(rumor, sender, recipient.PublicKey);

        Assert.Equal(Nip59.GiftWrapKind, wrap.Kind);
        Assert.True(wrap.Verify());
        Assert.NotEqual(sender.PublicKey, wrap.PubKey); // wrap is signed by an ephemeral key
        Assert.Contains(wrap.Tags, t => t.Count >= 2 && t[0] == "p" && t[1] == recipient.PublicKey.ToHex());

        var unwrapped = Nip59.Unwrap(wrap, recipient);
        Assert.Equal(sender.PublicKey, unwrapped.Sender);
        Assert.Equal(rumor.Kind, unwrapped.Kind);
        Assert.Equal(rumor.CreatedAt, unwrapped.CreatedAt);
        Assert.Equal(rumor.Content, unwrapped.Content);
        Assert.Equal(rumor.Tags.Count, unwrapped.Tags.Count);
    }

    [Fact]
    public void Wrap_UsesFreshEphemeralKeyPerCall()
    {
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();
        var rumor = MakeRumor();

        var w1 = Nip59.Wrap(rumor, sender, recipient.PublicKey);
        var w2 = Nip59.Wrap(rumor, sender, recipient.PublicKey);

        Assert.NotEqual(w1.PubKey, w2.PubKey);
        Assert.NotEqual(w1.Content, w2.Content);
    }

    [Fact]
    public void Wrap_JittersOuterTimestampBackward()
    {
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();

        long anchor = 1_700_000_000L;
        var wrap = Nip59.Wrap(MakeRumor() with { CreatedAt = anchor }, sender, recipient.PublicKey);

        Assert.InRange(wrap.CreatedAt, anchor - Nip59.MaxBackwardJitterSeconds, anchor);
    }

    [Fact]
    public void Unwrap_RejectsWrongRecipient()
    {
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();
        using var stranger = PrivateKey.Generate();

        var wrap = Nip59.Wrap(MakeRumor(), sender, recipient.PublicKey);
        Assert.Throws<CryptographicException>(() => Nip59.Unwrap(wrap, stranger));
    }

    [Fact]
    public void Unwrap_RejectsNonGiftWrapKind()
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

        Assert.Throws<ArgumentException>(() => Nip59.Unwrap(note, key));
    }

    [Fact]
    public void TryUnwrap_ReturnsTrueForValidRecipient()
    {
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();

        var wrap = Nip59.Wrap(MakeRumor("yo"), sender, recipient.PublicKey);
        Assert.True(Nip59.TryUnwrap(wrap, recipient, out var rumor));
        Assert.NotNull(rumor);
        Assert.Equal("yo", rumor.Content);
        Assert.Equal(sender.PublicKey, rumor.Sender);
    }

    [Fact]
    public void TryUnwrap_ReturnsFalseForWrongRecipient()
    {
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();
        using var stranger = PrivateKey.Generate();

        var wrap = Nip59.Wrap(MakeRumor(), sender, recipient.PublicKey);
        Assert.False(Nip59.TryUnwrap(wrap, stranger, out var rumor));
        Assert.Null(rumor);
    }

    [Fact]
    public void Unwrap_RecomputesRumorIdMatchesPayload()
    {
        // The UnwrappedRumor.RumorId field must equal the canonical id
        // computed from (sender, created_at, kind, tags, content).
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();
        var rumor = MakeRumor("identity-check");

        var wrap = Nip59.Wrap(rumor, sender, recipient.PublicKey);
        var u = Nip59.Unwrap(wrap, recipient);

        EventId expected = EventSerializer.ComputeId(
            sender.PublicKey, rumor.CreatedAt, rumor.Kind, rumor.Tags, rumor.Content);

        Assert.Equal(expected.ToHex(), u.RumorId.ToHex());
    }

    [Fact]
    public void Unwrap_RejectsTamperedRumorIdField()
    {
        // Forge a seal whose rumor JSON declares an id that doesn't match
        // its other fields. Nip59 must reject it at the id-recompute step.
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();
        using var ephemeral = PrivateKey.Generate();

        string forgedRumor = "{"
            + "\"id\":\"" + new string('0', 64) + "\","       // bogus id
            + "\"pubkey\":\"" + sender.PublicKey.ToHex() + "\","
            + "\"created_at\":1700000000,"
            + "\"kind\":9999,"
            + "\"tags\":[],"
            + "\"content\":\"hi\""
            + "}";

        var seal = new UnsignedEvent
        {
            PubKey = sender.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = Nip59.SealKind,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = Nip44.Encrypt(forgedRumor, sender, recipient.PublicKey),
        }.Sign(sender);

        var wrap = new UnsignedEvent
        {
            PubKey = ephemeral.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = Nip59.GiftWrapKind,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "p", recipient.PublicKey.ToHex() },
            },
            Content = Nip44.Encrypt(seal.ToJson(), ephemeral, recipient.PublicKey),
        }.Sign(ephemeral);

        var ex = Assert.Throws<CryptographicException>(() => Nip59.Unwrap(wrap, recipient));
        Assert.Contains("id", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Unwrap_RejectsRumorPubkeyMismatchWithSeal()
    {
        // Security-critical: an attacker who captures Alice's seal must not
        // be able to re-wrap it with a forged rumor pubkey to impersonate.
        using var alice = PrivateKey.Generate();
        using var mallory = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();
        using var ephemeral = PrivateKey.Generate();

        // Build a rumor that claims to be from Mallory, but seal it with Alice's key.
        var rumorPayload = new
        {
            pubkey = mallory.PublicKey.ToHex(),
            created_at = 1_700_000_000L,
            kind = 9999,
            tags = Array.Empty<object>(),
            content = "impersonation attempt",
        };
        // Compute the matching id so we don't fall over the earlier id-mismatch check.
        EventId id = EventSerializer.ComputeId(
            mallory.PublicKey, 1_700_000_000L, 9999,
            Array.Empty<IReadOnlyList<string>>(), "impersonation attempt");

        string forgedRumor = "{"
            + "\"id\":\"" + id.ToHex() + "\","
            + "\"pubkey\":\"" + mallory.PublicKey.ToHex() + "\","
            + "\"created_at\":1700000000,"
            + "\"kind\":9999,"
            + "\"tags\":[],"
            + "\"content\":\"impersonation attempt\""
            + "}";

        var seal = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = Nip59.SealKind,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = Nip44.Encrypt(forgedRumor, alice, recipient.PublicKey),
        }.Sign(alice);

        var wrap = new UnsignedEvent
        {
            PubKey = ephemeral.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = Nip59.GiftWrapKind,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "p", recipient.PublicKey.ToHex() },
            },
            Content = Nip44.Encrypt(seal.ToJson(), ephemeral, recipient.PublicKey),
        }.Sign(ephemeral);

        // Sanity-check the forged JSON parses as I expect.
        using (var doc = JsonDocument.Parse(forgedRumor))
        {
            Assert.Equal(mallory.PublicKey.ToHex(), doc.RootElement.GetProperty("pubkey").GetString());
        }

        Assert.Throws<CryptographicException>(() => Nip59.Unwrap(wrap, recipient));
    }

    [Fact]
    public void Unwrap_RejectsInnerEventThatsNotASeal()
    {
        // The encrypted inner is a kind-1 note instead of kind-13.
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();
        using var ephemeral = PrivateKey.Generate();

        var fakeSeal = new UnsignedEvent
        {
            PubKey = sender.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,                                       // NOT kind 13
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = Nip44.Encrypt("{}", sender, recipient.PublicKey),
        }.Sign(sender);

        var wrap = new UnsignedEvent
        {
            PubKey = ephemeral.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = Nip59.GiftWrapKind,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "p", recipient.PublicKey.ToHex() },
            },
            Content = Nip44.Encrypt(fakeSeal.ToJson(), ephemeral, recipient.PublicKey),
        }.Sign(ephemeral);

        var ex = Assert.Throws<CryptographicException>(() => Nip59.Unwrap(wrap, recipient));
        Assert.Contains("seal", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Wrap_ProducesRumorTagsThatRoundTrip()
    {
        using var sender = PrivateKey.Generate();
        using var recipient = PrivateKey.Generate();

        var rumor = new Rumor(
            Kind: 12345,
            CreatedAt: 1_700_000_000L,
            Tags: new IReadOnlyList<string>[]
            {
                new[] { "subject", "with spaces and \"quotes\"" },
                new[] { "t", "tag-a", "tag-b" },
                new[] { "expiration", "1700003600" },
            },
            Content: "preserve tags exactly");

        var wrap = Nip59.Wrap(rumor, sender, recipient.PublicKey);
        var u = Nip59.Unwrap(wrap, recipient);

        Assert.Equal(rumor.Tags.Count, u.Tags.Count);
        for (int i = 0; i < rumor.Tags.Count; i++)
        {
            Assert.Equal(rumor.Tags[i].Count, u.Tags[i].Count);
            for (int j = 0; j < rumor.Tags[i].Count; j++)
            {
                Assert.Equal(rumor.Tags[i][j], u.Tags[i][j]);
            }
        }
    }
}
