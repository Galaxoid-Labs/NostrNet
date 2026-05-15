// SPDX-License-Identifier: MIT
//
// NIP-04 decode tests. The spec has no canonical interop vector suite
// (it predates the paulmillr-style vector culture), so the coverage here
// is roundtrip + negative shape. The ECDH primitive
// (Secp256k1.EcdhSharedXCoord) is exercised against vectors by the
// NIP-44 suite, so the only thing this file is uniquely validating is
// the content-format parsing and AES-256-CBC wiring.

using System.Security.Cryptography;
using NostrNet.Crypto;
using NostrNet.Cryptography;
using NostrNet.Events;
using NostrNet.Keys;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Tests.Crypto;

public class Nip04Tests
{
    [Fact]
    public void Decrypt_RoundTripsArbitraryPlaintext()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        const string Message = "hey bob, can you read this legacy DM?";

        string content = LegacyEncrypt(Message, alice, bob.PublicKey);

        string decrypted = Nip04.Decrypt(content, bob, alice.PublicKey);
        Assert.Equal(Message, decrypted);
    }

    [Fact]
    public void Decrypt_IsSymmetric_BothPartiesRecoverPlaintext()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        const string Message = "ECDH is symmetric so both sides decrypt the same ciphertext";

        string content = LegacyEncrypt(Message, alice, bob.PublicKey);

        Assert.Equal(Message, Nip04.Decrypt(content, bob, alice.PublicKey));
        Assert.Equal(Message, Nip04.Decrypt(content, alice, bob.PublicKey));
    }

    [Fact]
    public void TryDecrypt_InboundEvent_IdentifiesSenderAsPeer()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        const string Message = "from alice to bob";

        var ev = BuildKind4Event(Message, sender: alice, recipient: bob.PublicKey);

        Assert.True(Nip04.TryDecrypt(ev, bob, out string? plaintext, out PublicKey? peer));
        Assert.Equal(Message, plaintext);
        Assert.Equal(alice.PublicKey, peer);
    }

    [Fact]
    public void TryDecrypt_OutboundEvent_IdentifiesRecipientAsPeer()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        const string Message = "I want to read what I sent earlier";

        // Alice composed it; she reads her own sent DM.
        var ev = BuildKind4Event(Message, sender: alice, recipient: bob.PublicKey);

        Assert.True(Nip04.TryDecrypt(ev, alice, out string? plaintext, out PublicKey? peer));
        Assert.Equal(Message, plaintext);
        Assert.Equal(bob.PublicKey, peer);
    }

    [Fact]
    public void TryDecrypt_WrongKey_ReturnsFalse()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        using var eve = PrivateKey.Generate();

        var ev = BuildKind4Event("not for eve", sender: alice, recipient: bob.PublicKey);

        Assert.False(Nip04.TryDecrypt(ev, eve, out string? plaintext, out PublicKey? peer));
        Assert.Null(plaintext);
        Assert.Null(peer);
    }

    [Fact]
    public void TryDecrypt_NonKind4Event_ReturnsFalse()
    {
        using var alice = PrivateKey.Generate();

        var ev = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "plain text note",
        }.Sign(alice);

        Assert.False(Nip04.TryDecrypt(ev, alice, out _, out _));
    }

    [Fact]
    public void TryDecrypt_OutboundWithoutPTag_ReturnsFalse()
    {
        using var alice = PrivateKey.Generate();

        // A kind-4 event from alice with no p tag — peer can't be resolved.
        var ev = new UnsignedEvent
        {
            PubKey = alice.PublicKey,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = Nip04.Kind,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "irrelevant",
        }.Sign(alice);

        Assert.False(Nip04.TryDecrypt(ev, alice, out _, out _));
    }

    [Fact]
    public void Decrypt_MissingIvSeparator_Throws()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        Assert.Throws<FormatException>(() =>
            Nip04.Decrypt("notavalidpayload", alice, bob.PublicKey));
    }

    [Fact]
    public void Decrypt_WrongIvLength_Throws()
    {
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        string content = "AAAA?iv=AAAA"; // valid base64 but iv decodes to 3 bytes
        Assert.Throws<FormatException>(() =>
            Nip04.Decrypt(content, alice, bob.PublicKey));
    }

    // ────────────────────────────────────────────────────────────
    // Test-only NIP-04 encrypt helper. Not in production code —
    // producing new NIP-04 messages is actively harmful (no MAC, the
    // scheme is deprecated). Lives here so the roundtrip tests have a
    // counterpart to Nip04.Decrypt without bringing back the encrypt
    // surface.
    // ────────────────────────────────────────────────────────────
    private static string LegacyEncrypt(string plaintext, PrivateKey senderPriv, PublicKey recipientPub)
    {
        Span<byte> privBytes = stackalloc byte[PrivateKey.Size];
        Span<byte> pubBytes = stackalloc byte[PublicKey.Size];
        Span<byte> sharedKey = stackalloc byte[32];

        senderPriv.CopyTo(privBytes);
        recipientPub.CopyTo(pubBytes);
        Secp256k1.EcdhSharedXCoord(privBytes, pubBytes, sharedKey);

        byte[] iv = RandomNumberGenerator.GetBytes(16);

        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = sharedKey.ToArray();
        aes.IV = iv;

        byte[] ciphertext = aes.EncryptCbc(SysEncoding.UTF8.GetBytes(plaintext), iv, PaddingMode.PKCS7);

        CryptographicOperations.ZeroMemory(privBytes);
        CryptographicOperations.ZeroMemory(sharedKey);

        return $"{Convert.ToBase64String(ciphertext)}?iv={Convert.ToBase64String(iv)}";
    }

    private static NostrEvent BuildKind4Event(string plaintext, PrivateKey sender, PublicKey recipient)
    {
        string content = LegacyEncrypt(plaintext, sender, recipient);
        return new UnsignedEvent
        {
            PubKey = sender.PublicKey,
            CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Kind = Nip04.Kind,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "p", recipient.ToHex() },
            },
            Content = content,
        }.Sign(sender);
    }
}
