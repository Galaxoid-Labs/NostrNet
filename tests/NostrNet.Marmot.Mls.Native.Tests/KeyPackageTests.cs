// SPDX-License-Identifier: MIT
//
// Verifies BuildKeyPackage / ParseKeyPackage round-trip through the
// OpenMLS-backed FFI. Cross-validates with NostrNet.Marmot envelope
// types so we know the bytes we emit are recognizable as MLS.

using NostrNet.Keys;
using NostrNet.Marmot.Events;

namespace NostrNet.Marmot.Mls.Native.Tests;

public class KeyPackageTests
{
    [Fact]
    public async Task BuildKeyPackage_ProducesNonEmptyBundleAndRef()
    {
        using var provider = new OpenMlsProvider();
        using var key = PrivateKey.Generate();

        var bundle = await provider.BuildKeyPackageAsync(
            identityPubkey: key.PublicKey,
            ciphersuite: 0x0001,
            extensions: new ushort[] { 0xF2EE },
            proposals: Array.Empty<ushort>());

        Assert.NotNull(bundle);
        Assert.NotEmpty(bundle.BundleBytes);
        Assert.Equal(0x0001, bundle.Ciphersuite);
        Assert.Equal("1.0", bundle.ProtocolVersion);
        Assert.NotNull(bundle.KeyPackageRef);
        Assert.Equal(64, bundle.KeyPackageRef.Length); // 32 bytes hex = 64 chars
    }

    [Fact]
    public async Task BuildKeyPackage_FreshKeysPerCall()
    {
        using var provider = new OpenMlsProvider();
        using var key = PrivateKey.Generate();

        var b1 = await provider.BuildKeyPackageAsync(key.PublicKey, 0x0001, Array.Empty<ushort>(), Array.Empty<ushort>());
        var b2 = await provider.BuildKeyPackageAsync(key.PublicKey, 0x0001, Array.Empty<ushort>(), Array.Empty<ushort>());

        // Each KeyPackage carries fresh init/encryption/signature keys.
        Assert.NotEqual(b1.KeyPackageRef, b2.KeyPackageRef);
        Assert.NotEqual(Convert.ToHexString(b1.BundleBytes), Convert.ToHexString(b2.BundleBytes));
    }

    [Fact]
    public async Task ParseKeyPackage_RoundTripsBuiltBundle()
    {
        using var provider = new OpenMlsProvider();
        using var key = PrivateKey.Generate();

        var built = await provider.BuildKeyPackageAsync(key.PublicKey, 0x0001, Array.Empty<ushort>(), Array.Empty<ushort>());
        var parsed = await provider.ParseKeyPackageAsync(built.BundleBytes);

        Assert.Equal(key.PublicKey, parsed.IdentityPubkey);
        Assert.Equal(0x0001, parsed.Ciphersuite);
        Assert.Equal(built.KeyPackageRef, parsed.KeyPackageRef);
    }

    [Fact]
    public async Task BundleBytes_ParseAsMarmotKeyPackageEvent()
    {
        // The bytes we emit should plug into NostrNet.Marmot envelope
        // types unchanged. This verifies wire compatibility with the
        // rest of NostrNet.
        using var provider = new OpenMlsProvider();
        using var key = PrivateKey.Generate();

        var built = await provider.BuildKeyPackageAsync(
            key.PublicKey, 0x0001,
            new ushort[] { 0xF2EE },
            Array.Empty<ushort>());

        var kpEvent = KeyPackageEvent.Create("default")
            .WithBundleBytes(built.BundleBytes)
            .WithCiphersuite(built.Ciphersuite)
            .WithExtension(0xF2EE)
            .WithKeyPackageRef(built.KeyPackageRef!)
            .WithRelay("wss://relay.example")
            .Sign(key);

        Assert.True(kpEvent.Verify());

        var roundTripped = KeyPackageEvent.FromEvent(kpEvent);
        Assert.Equal(built.BundleBytes, roundTripped.KeyPackageBundleBytes);

        // And the OpenMLS provider can parse it back.
        var parsed = await provider.ParseKeyPackageAsync(roundTripped.KeyPackageBundleBytes);
        Assert.Equal(key.PublicKey, parsed.IdentityPubkey);
    }

    [Fact]
    public async Task BuildKeyPackage_RejectsUnsupportedCiphersuite()
    {
        using var provider = new OpenMlsProvider();
        using var key = PrivateKey.Generate();

        await Assert.ThrowsAsync<NotSupportedException>(
            async () => await provider.BuildKeyPackageAsync(
                key.PublicKey,
                ciphersuite: 0xBEEF,
                Array.Empty<ushort>(),
                Array.Empty<ushort>()));
    }
}
