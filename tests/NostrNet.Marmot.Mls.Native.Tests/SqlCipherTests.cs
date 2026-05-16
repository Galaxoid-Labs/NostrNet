// SPDX-License-Identifier: MIT
//
// Encryption-specific behavior of the SQLCipher-backed OpenMlsProvider.
// Plain functional / persistence behavior is covered by the existing
// PersistenceTests and DbHelpersTests, which now also run through the
// SQLCipher pager; this file pins the wrong-key / wrong-length-key /
// reopen-with-different-key paths that only matter with encryption on.

using NostrNet.Keys;
using NostrNet.Marmot;

namespace NostrNet.Marmot.Mls.Native.Tests;

public class SqlCipherTests
{
    private static readonly byte[] KeyA = Enumerable.Repeat((byte)0x11, 32).ToArray();
    private static readonly byte[] KeyB = Enumerable.Repeat((byte)0x22, 32).ToArray();

    private static string TempSqlitePath() =>
        Path.Combine(Path.GetTempPath(), $"nn-sqlcipher-{Guid.NewGuid():N}.sqlite");

    private static void DeleteSidecars(string path)
    {
        File.Delete(path);
        File.Delete(path + "-shm");
        File.Delete(path + "-wal");
    }

    [Fact]
    public async Task RoundTrip_SameKey_RecoversState()
    {
        string path = TempSqlitePath();
        try
        {
            byte[] groupId;
            {
                using var aliceKey = PrivateKey.Generate();
                using var bobKey = PrivateKey.Generate();
                using var alice = OpenMlsProvider.OpenAtPath(path, KeyA);
                using var bob = new OpenMlsProvider();

                var bobKp = await MarmotChat.BuildKeyPackageEventAsync(bob, bobKey, null, new[] { "wss://x" });
                var started = await MarmotChat.StartConversationAsync(
                    alice, aliceKey, bobKp, "sealed", new[] { "wss://x" });
                groupId = started.Conversation.NostrGroupId;
            }

            // Reopen with the same key — state must come back.
            using var alice2 = OpenMlsProvider.OpenAtPath(path, KeyA);
            var groups = await alice2.ListGroupsAsync();
            Assert.Single(groups);
            Assert.Equal(groupId, groups[0].NostrGroupId);
        }
        finally
        {
            DeleteSidecars(path);
        }
    }

    [Fact]
    public async Task WrongKey_ThrowsInvalidMlsKeyException()
    {
        string path = TempSqlitePath();
        try
        {
            // Create + populate with KeyA.
            {
                using var aliceKey = PrivateKey.Generate();
                using var alice = OpenMlsProvider.OpenAtPath(path, KeyA);
                await alice.StateInfoAsync();  // forces at least one write
            }

            // Reopening with KeyB must fail with the typed exception.
            var ex = Assert.Throws<InvalidMlsKeyException>(() =>
                OpenMlsProvider.OpenAtPath(path, KeyB));
            Assert.Contains("invalid MLS state key", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            DeleteSidecars(path);
        }
    }

    [Fact]
    public void WrongLengthKey_ThrowsArgumentException()
    {
        string path = TempSqlitePath();
        try
        {
            // Too short.
            Assert.Throws<ArgumentException>(() =>
                OpenMlsProvider.OpenAtPath(path, new byte[16]));

            // Too long.
            Assert.Throws<ArgumentException>(() =>
                OpenMlsProvider.OpenAtPath(path, new byte[64]));

            // Empty.
            Assert.Throws<ArgumentException>(() =>
                OpenMlsProvider.OpenAtPath(path, ReadOnlySpan<byte>.Empty));
        }
        finally
        {
            DeleteSidecars(path);
        }
    }

    [Fact]
    public async Task FileIsActuallyEncrypted_PlainOpenWithoutKeyFails()
    {
        // Pragmatic check that we're getting SQLCipher behavior, not
        // accidentally falling through to plain SQLite. A SQLCipher-
        // encrypted file:
        //   - can be opened with a sqlite3 client + PRAGMA key = "x'...'"
        //   - cannot be opened as plain sqlite (the header is encrypted)
        //
        // We can't easily run a sqlite3 CLI from the test, but we can
        // re-open with an obviously-wrong key (32 zero bytes) and assert
        // the typed wrong-key exception fires. If the file were plain
        // SQLite the open would succeed and this test would catch the
        // regression.
        string path = TempSqlitePath();
        try
        {
            {
                using var alice = OpenMlsProvider.OpenAtPath(path, KeyA);
                await alice.StateInfoAsync();
            }

            byte[] zeroKey = new byte[32];
            Assert.Throws<InvalidMlsKeyException>(() =>
                OpenMlsProvider.OpenAtPath(path, zeroKey));
        }
        finally
        {
            DeleteSidecars(path);
        }
    }
}
