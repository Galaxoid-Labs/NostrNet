// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using NostrNet.Events;
using NostrNet.Marmot;
using NostrNet.Marmot.Events;

namespace NostrNet.Marmot.Tests.Events;

public class GroupEventTests
{
    private static byte[] RandomBytes(int length, int seed)
    {
        byte[] b = new byte[length];
        new Random(seed).NextBytes(b);
        return b;
    }

    [Fact]
    public void Encrypt_AndDecrypt_RoundTrip()
    {
        byte[] mlsMessage = RandomBytes(200, 1);
        byte[] exporterSecret = RandomBytes(32, 2);
        byte[] groupId = RandomBytes(32, 3);

        var ev = GroupEvent.Build(mlsMessage, exporterSecret, groupId);
        Assert.Equal(MarmotKinds.GroupEvent, ev.Kind);
        Assert.True(ev.Verify());

        var decrypted = GroupEvent.Decrypt(ev, exporterSecret);
        Assert.Equal(mlsMessage, decrypted.MlsMessageBytes);
        Assert.Equal(groupId, decrypted.NostrGroupId);
        Assert.Null(decrypted.Expiration);
    }

    [Fact]
    public void Encrypt_UsesEphemeralKeyDifferentEachTime()
    {
        byte[] mlsMessage = RandomBytes(100, 1);
        byte[] exporterSecret = RandomBytes(32, 2);
        byte[] groupId = RandomBytes(32, 3);

        var ev1 = GroupEvent.Build(mlsMessage, exporterSecret, groupId);
        var ev2 = GroupEvent.Build(mlsMessage, exporterSecret, groupId);

        // Ephemeral keys MUST NOT be reused across events.
        Assert.NotEqual(ev1.PubKey, ev2.PubKey);
    }

    [Fact]
    public void DisappearingMessages_AddsExpirationTag()
    {
        byte[] mlsMessage = RandomBytes(50, 1);
        byte[] exporterSecret = RandomBytes(32, 2);
        byte[] groupId = RandomBytes(32, 3);

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var ev = GroupEvent.Build(
            mlsMessage, exporterSecret, groupId,
            disappearingMessageDuration: TimeSpan.FromHours(1),
            createdAt: now);

        // The event has the NIP-40 expiration tag, set to created_at + 3600.
        string? expTag = ev.Tags.FirstValue("expiration");
        Assert.NotNull(expTag);
        Assert.Equal((now + 3600).ToString(), expTag);

        var decrypted = GroupEvent.Decrypt(ev, exporterSecret);
        Assert.NotNull(decrypted.Expiration);
    }

    [Fact]
    public void Decrypt_FailsWithWrongKey()
    {
        byte[] mlsMessage = RandomBytes(64, 1);
        byte[] exporterSecret = RandomBytes(32, 2);
        byte[] groupId = RandomBytes(32, 3);
        byte[] wrongKey = RandomBytes(32, 99);

        var ev = GroupEvent.Build(mlsMessage, exporterSecret, groupId);

        // ChaCha20-Poly1305 auth failure surfaces as CryptographicException.
        Assert.ThrowsAny<CryptographicException>(() => GroupEvent.Decrypt(ev, wrongKey));
    }

    [Fact]
    public void TryDecrypt_ReturnsFalseOnAuthFailure()
    {
        byte[] mlsMessage = RandomBytes(64, 1);
        byte[] exporterSecret = RandomBytes(32, 2);
        byte[] groupId = RandomBytes(32, 3);
        byte[] wrongKey = RandomBytes(32, 99);

        var ev = GroupEvent.Build(mlsMessage, exporterSecret, groupId);
        Assert.False(GroupEvent.TryDecrypt(ev, wrongKey, out var decrypted));
        Assert.Null(decrypted);
    }

    [Fact]
    public void Build_RejectsWrongLengthSecret()
    {
        byte[] mlsMessage = RandomBytes(50, 1);
        byte[] groupId = RandomBytes(32, 3);

        Assert.Throws<ArgumentException>(() =>
            GroupEvent.Build(mlsMessage, RandomBytes(16, 2), groupId));
    }

    [Fact]
    public void Build_RejectsWrongLengthGroupId()
    {
        byte[] mlsMessage = RandomBytes(50, 1);
        byte[] secret = RandomBytes(32, 2);

        Assert.Throws<ArgumentException>(() =>
            GroupEvent.Build(mlsMessage, secret, RandomBytes(31, 3)));
    }

    [Fact]
    public void Build_RejectsEmptyMessage()
    {
        byte[] secret = RandomBytes(32, 2);
        byte[] groupId = RandomBytes(32, 3);

        Assert.Throws<ArgumentException>(() =>
            GroupEvent.Build(ReadOnlySpan<byte>.Empty, secret, groupId));
    }

    [Fact]
    public void Decrypt_RejectsWrongKind()
    {
        using var key = NostrNet.Keys.PrivateKey.Generate();
        var note = new NostrNet.Events.UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = 1,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = "",
        }.Sign(key);

        Assert.Throws<ArgumentException>(() => GroupEvent.Decrypt(note, RandomBytes(32, 1)));
    }

    [Fact]
    public void Decrypt_RejectsBadHTag()
    {
        using var key = NostrNet.Keys.PrivateKey.Generate();
        // Forge a kind-445 with a wrong-length h tag and valid base64.
        var ev = new NostrNet.Events.UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = MarmotKinds.GroupEvent,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "h", "deadbeef" },   // way too short
            },
            Content = Convert.ToBase64String(new byte[40]),
        }.Sign(key);

        Assert.Throws<FormatException>(() => GroupEvent.Decrypt(ev, RandomBytes(32, 1)));
    }

    [Fact]
    public void Decrypt_RejectsTooShortContent()
    {
        using var key = NostrNet.Keys.PrivateKey.Generate();
        byte[] groupId = RandomBytes(32, 3);

        var ev = new NostrNet.Events.UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = MarmotKinds.GroupEvent,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "h", Convert.ToHexStringLower(groupId) },
            },
            // 20 bytes is less than the 28-byte minimum (12 nonce + 16 tag).
            Content = Convert.ToBase64String(new byte[20]),
        }.Sign(key);

        Assert.Throws<FormatException>(() => GroupEvent.Decrypt(ev, RandomBytes(32, 1)));
    }
}
