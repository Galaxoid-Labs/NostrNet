// SPDX-License-Identifier: MIT
//
// Smoke tests for the state-DB helper APIs on OpenMlsProvider:
// DeleteGroupAsync, VacuumAsync, StateInfoAsync, WipeStateAsync.

using NostrNet.Keys;
using NostrNet.Marmot;

namespace NostrNet.Marmot.Mls.Native.Tests;

public class DbHelpersTests
{
    private static string TempSqlitePath() =>
        Path.Combine(Path.GetTempPath(), $"nn-dbhelpers-{Guid.NewGuid():N}.db");

    [Fact]
    public async Task DeleteGroup_RemovesFromList()
    {
        using var aliceKey = PrivateKey.Generate();
        using var bobKey = PrivateKey.Generate();
        using var alice = new OpenMlsProvider();
        using var bob = new OpenMlsProvider();
        var relays = new[] { "wss://relay.example" };

        var bobKp = await MarmotChat.BuildKeyPackageEventAsync(bob, bobKey, null, relays);
        var started = await MarmotChat.StartConversationAsync(alice, aliceKey, bobKp, "t", relays);

        var before = await alice.ListGroupsAsync();
        Assert.Single(before);
        Assert.Equal(started.Conversation.NostrGroupId, before[0].NostrGroupId);

        await alice.DeleteGroupAsync(started.Conversation.NostrGroupId);

        var after = await alice.ListGroupsAsync();
        Assert.Empty(after);
    }

    [Fact]
    public async Task StateInfo_ReportsPathSizeAndGroupCount()
    {
        var path = TempSqlitePath();
        try
        {
            using var aliceKey = PrivateKey.Generate();
            using var bobKey = PrivateKey.Generate();
            using var alice = OpenMlsProvider.OpenAtPath(path);
            using var bob = new OpenMlsProvider();
            var relays = new[] { "wss://relay.example" };

            var info0 = await alice.StateInfoAsync();
            Assert.Equal(path, info0.Path);
            Assert.Equal(0, info0.GroupCount);
            Assert.True(info0.SizeOnDiskBytes >= 0);

            var bobKp = await MarmotChat.BuildKeyPackageEventAsync(bob, bobKey, null, relays);
            _ = await MarmotChat.StartConversationAsync(alice, aliceKey, bobKp, "t", relays);

            var info1 = await alice.StateInfoAsync();
            Assert.Equal(1, info1.GroupCount);
            Assert.True(info1.SizeOnDiskBytes > 0);
        }
        finally
        {
            File.Delete(path);
            File.Delete(path + "-shm");
            File.Delete(path + "-wal");
        }
    }

    [Fact]
    public async Task StateInfo_InMemory_PathIsNullAndSizeZero()
    {
        using var alice = new OpenMlsProvider();
        var info = await alice.StateInfoAsync();
        Assert.Null(info.Path);
        Assert.Equal(0, info.SizeOnDiskBytes);
        Assert.Equal(0, info.GroupCount);
    }

    [Fact]
    public async Task Vacuum_IsNoOpForInMemory_AndSucceedsForFileBacked()
    {
        // In-memory: should be a clean no-op.
        using (var inmem = new OpenMlsProvider())
        {
            await inmem.VacuumAsync();
        }

        // File-backed: just verify the call returns without exception.
        var path = TempSqlitePath();
        try
        {
            using var file = OpenMlsProvider.OpenAtPath(path);
            await file.VacuumAsync();
        }
        finally
        {
            File.Delete(path);
            File.Delete(path + "-shm");
            File.Delete(path + "-wal");
        }
    }

    [Fact]
    public async Task WipeState_DeletesFile_AndDisposesProvider()
    {
        var path = TempSqlitePath();
        var prov = OpenMlsProvider.OpenAtPath(path);
        // touch the file
        await prov.StateInfoAsync();
        Assert.True(File.Exists(path));

        await prov.WipeStateAsync();
        Assert.False(File.Exists(path));
        Assert.False(File.Exists(path + "-shm"));
        Assert.False(File.Exists(path + "-wal"));
    }

    [Fact]
    public async Task WipeState_OnInMemory_Throws()
    {
        var prov = new OpenMlsProvider();
        await Assert.ThrowsAsync<InvalidOperationException>(() => prov.WipeStateAsync());
        prov.Dispose();
    }
}
