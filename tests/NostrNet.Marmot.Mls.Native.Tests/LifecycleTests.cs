// SPDX-License-Identifier: MIT
//
// Phase 1 smoke tests for the OpenMLS FFI bridge: just exercise
// provider new/free and the ABI version handshake.

using NostrNet.Marmot.Mls.Native;

namespace NostrNet.Marmot.Mls.Native.Tests;

public class LifecycleTests
{
    [Fact]
    public void NativeAbiVersion_Is7()
    {
        Assert.Equal(7u, OpenMlsProvider.NativeAbiVersion());
    }

    [Fact]
    public void Provider_LifecycleRoundTrips()
    {
        // Spin up several providers in sequence — verifies no resource
        // leaks crash the process and that the SafeHandle path works.
        for (int i = 0; i < 5; i++)
        {
            using var provider = new OpenMlsProvider();
            Assert.NotNull(provider);
        }
    }

    [Fact]
    public void Provider_DisposeIsIdempotent()
    {
        var provider = new OpenMlsProvider();
        provider.Dispose();
        provider.Dispose(); // must not throw
    }
}
