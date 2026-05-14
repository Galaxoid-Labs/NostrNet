// SPDX-License-Identifier: MIT
//
// Tests for the Marmot Group Data extension (MIP-01, 0xF2EE) wire codec.

using NostrNet.Keys;
using NostrNet.Marmot.GroupData;

namespace NostrNet.Marmot.Tests.GroupData;

public class MarmotGroupDataExtensionTests
{
    private static byte[] RandomBytes(int length, int seed = 1)
    {
        byte[] buf = new byte[length];
        new Random(seed).NextBytes(buf);
        return buf;
    }

    private static PublicKey RandomPubkey(int seed) => new(RandomBytes(32, seed));

    [Fact]
    public void RoundTrip_MinimalExtension()
    {
        var ext = new MarmotGroupDataExtension
        {
            NostrGroupId = RandomBytes(32, 1),
            AdminPubkeys = new[] { RandomPubkey(2) },
            Relays = new[] { "wss://relay.example.com" },
        };

        var bytes = ext.Encode();
        var parsed = MarmotGroupDataExtension.Parse(bytes);

        Assert.Equal(MarmotGroupDataExtension.CurrentVersion, parsed.Version);
        Assert.Equal(ext.NostrGroupId, parsed.NostrGroupId);
        Assert.Equal(string.Empty, parsed.Name);
        Assert.Equal(string.Empty, parsed.Description);
        Assert.Single(parsed.AdminPubkeys);
        Assert.Equal(ext.AdminPubkeys[0], parsed.AdminPubkeys[0]);
        Assert.Single(parsed.Relays);
        Assert.Equal("wss://relay.example.com", parsed.Relays[0]);
        Assert.False(parsed.HasImage);
        Assert.Null(parsed.DisappearingMessageDuration);
    }

    [Fact]
    public void RoundTrip_FullExtensionIncludingImageAndDisappearing()
    {
        var ext = new MarmotGroupDataExtension
        {
            NostrGroupId = RandomBytes(32, 1),
            Name = "Friends of Bob",
            Description = "A private group chat for Bob's close friends",
            AdminPubkeys = new[] { RandomPubkey(2), RandomPubkey(3) },
            Relays = new[] { "wss://relay.damus.io", "wss://nos.lol", "wss://relay.nostr.band" },
            ImageHash = RandomBytes(32, 10),
            ImageKey = RandomBytes(32, 11),
            ImageNonce = RandomBytes(12, 12),
            ImageUploadKey = RandomBytes(32, 13),
            DisappearingMessageDuration = TimeSpan.FromHours(24),
        };

        var parsed = MarmotGroupDataExtension.Parse(ext.Encode());

        Assert.Equal("Friends of Bob", parsed.Name);
        Assert.Equal("A private group chat for Bob's close friends", parsed.Description);
        Assert.Equal(2, parsed.AdminPubkeys.Count);
        Assert.Equal(3, parsed.Relays.Count);
        Assert.True(parsed.HasImage);
        Assert.Equal(ext.ImageHash, parsed.ImageHash);
        Assert.Equal(ext.ImageKey, parsed.ImageKey);
        Assert.Equal(ext.ImageNonce, parsed.ImageNonce);
        Assert.Equal(ext.ImageUploadKey, parsed.ImageUploadKey);
        Assert.Equal(TimeSpan.FromHours(24), parsed.DisappearingMessageDuration);
    }

    [Fact]
    public void RoundTrip_Utf8MultiByteNameAndDescription()
    {
        var ext = new MarmotGroupDataExtension
        {
            NostrGroupId = RandomBytes(32),
            Name = "日本語グループ",       // 7 chars, 21 UTF-8 bytes
            Description = "Description with emoji 🚀 and accented éàü",
            AdminPubkeys = new[] { RandomPubkey(2) },
            Relays = new[] { "wss://relay.example.com" },
        };

        var parsed = MarmotGroupDataExtension.Parse(ext.Encode());
        Assert.Equal(ext.Name, parsed.Name);
        Assert.Equal(ext.Description, parsed.Description);
    }

    [Fact]
    public void Parse_RejectsWrongVersion()
    {
        // Build a wire blob with version 999 (a future version we don't grok).
        byte[] wire = new byte[64];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(wire, 999);
        RandomBytes(32).CopyTo(wire, 2);
        var ex = Assert.Throws<InvalidDataException>(() => MarmotGroupDataExtension.Parse(wire));
        Assert.Contains("version", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_RejectsDuplicateAdminPubkeys()
    {
        var dup = RandomPubkey(2);
        var ext = new MarmotGroupDataExtension
        {
            NostrGroupId = RandomBytes(32),
            AdminPubkeys = new[] { dup, dup },
            Relays = new[] { "wss://relay.example.com" },
        };

        Assert.Throws<InvalidDataException>(() => MarmotGroupDataExtension.Parse(ext.Encode()));
    }

    [Fact]
    public void Encode_RejectsPartialImageFields()
    {
        var ext = new MarmotGroupDataExtension
        {
            NostrGroupId = RandomBytes(32),
            AdminPubkeys = new[] { RandomPubkey(2) },
            Relays = new[] { "wss://relay.example.com" },
            ImageHash = RandomBytes(32),
            // ImageKey, ImageNonce, ImageUploadKey deliberately left null
        };

        Assert.Throws<InvalidOperationException>(() => ext.Encode());
    }

    [Fact]
    public void Encode_RejectsZeroDisappearingDuration()
    {
        var ext = new MarmotGroupDataExtension
        {
            NostrGroupId = RandomBytes(32),
            AdminPubkeys = new[] { RandomPubkey(2) },
            Relays = new[] { "wss://relay.example.com" },
            DisappearingMessageDuration = TimeSpan.Zero,
        };

        Assert.Throws<InvalidOperationException>(() => ext.Encode());
    }

    [Fact]
    public void Encode_RejectsWrongNostrGroupIdLength()
    {
        var ext = new MarmotGroupDataExtension
        {
            NostrGroupId = RandomBytes(31),       // one byte short
            AdminPubkeys = new[] { RandomPubkey(2) },
            Relays = new[] { "wss://relay.example.com" },
        };

        Assert.Throws<InvalidOperationException>(() => ext.Encode());
    }

    [Fact]
    public void RoundTrip_EmptyAdminsAndRelays()
    {
        // Edge case: parser tolerates empty vectors (real groups would
        // reject these at a higher layer, but the codec must round-trip
        // them).
        var ext = new MarmotGroupDataExtension
        {
            NostrGroupId = RandomBytes(32),
            AdminPubkeys = Array.Empty<PublicKey>(),
            Relays = Array.Empty<string>(),
        };

        var parsed = MarmotGroupDataExtension.Parse(ext.Encode());
        Assert.Empty(parsed.AdminPubkeys);
        Assert.Empty(parsed.Relays);
    }

    [Fact]
    public void TryParse_ReturnsFalseForMalformedInput()
    {
        // Random bytes are very unlikely to parse as a valid extension.
        byte[] garbage = RandomBytes(64, 99);
        Assert.False(MarmotGroupDataExtension.TryParse(garbage, out var ext));
        Assert.Null(ext);
    }

    [Fact]
    public void ManyAdmins_ForcesLongerVarintLengthPrefix()
    {
        // 3 admins * 32 = 96 bytes > 63 (1-byte varint boundary).
        // Verifies the 2-byte varint path is exercised.
        var admins = Enumerable.Range(2, 3).Select(RandomPubkey).ToArray();
        var ext = new MarmotGroupDataExtension
        {
            NostrGroupId = RandomBytes(32),
            AdminPubkeys = admins,
            Relays = new[] { "wss://relay.example.com" },
        };

        var parsed = MarmotGroupDataExtension.Parse(ext.Encode());
        Assert.Equal(admins.Length, parsed.AdminPubkeys.Count);
    }
}
