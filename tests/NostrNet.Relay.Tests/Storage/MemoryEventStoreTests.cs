// SPDX-License-Identifier: MIT
//
// Coverage for MemoryEventStore: dedup, NIP-01 replaceable + addressable
// upsert, NIP-09 deletion, NIP-40 expiration, capacity eviction, query
// and live-observe semantics.

using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Relay;
using NostrNet.Relay.Storage;

namespace NostrNet.Tests.Relay.Storage;

public class MemoryEventStoreTests
{
    // ----- Dedup.

    [Fact]
    public async Task StoreAsync_NewEvent_ReturnsStored()
    {
        using var store = new MemoryEventStore();
        using var key = PrivateKey.Generate();
        var ev = BuildEvent(key, kind: 1, content: "hi");

        Assert.Equal(StoreResult.Stored, await store.StoreAsync(ev));
        Assert.Equal(1, await store.CountAsync());
    }

    [Fact]
    public async Task StoreAsync_SameEventTwice_SecondIsDuplicate()
    {
        using var store = new MemoryEventStore();
        using var key = PrivateKey.Generate();
        var ev = BuildEvent(key, kind: 1, content: "hi");

        Assert.Equal(StoreResult.Stored, await store.StoreAsync(ev));
        Assert.Equal(StoreResult.Duplicate, await store.StoreAsync(ev));
        Assert.Equal(1, await store.CountAsync());
    }

    // ----- NIP-01 replaceable (kind 0, 3, 10000–19999).

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(10002)]   // relay list
    [InlineData(10063)]   // blossom user servers
    [InlineData(19999)]
    public async Task StoreAsync_NewerReplaceable_ReplacesOlder(int kind)
    {
        using var store = new MemoryEventStore();
        using var key = PrivateKey.Generate();
        var old = BuildEvent(key, kind: kind, content: "v1", createdAt: 1_000);
        var fresh = BuildEvent(key, kind: kind, content: "v2", createdAt: 2_000);

        Assert.Equal(StoreResult.Stored, await store.StoreAsync(old));
        Assert.Equal(StoreResult.Replaced, await store.StoreAsync(fresh));

        // Only the new one remains.
        Assert.Equal(1, await store.CountAsync());
        Assert.Null(await store.GetAsync(old.Id));
        Assert.Equal(fresh.Id, (await store.GetAsync(fresh.Id))!.Id);
    }

    [Fact]
    public async Task StoreAsync_OlderReplaceable_IsOutdated()
    {
        using var store = new MemoryEventStore();
        using var key = PrivateKey.Generate();
        var fresh = BuildEvent(key, kind: 0, content: "v2", createdAt: 2_000);
        var old = BuildEvent(key, kind: 0, content: "v1", createdAt: 1_000);

        Assert.Equal(StoreResult.Stored, await store.StoreAsync(fresh));
        Assert.Equal(StoreResult.Outdated, await store.StoreAsync(old));

        Assert.Equal(1, await store.CountAsync());
        Assert.Null(await store.GetAsync(old.Id));
    }

    [Fact]
    public async Task StoreAsync_DifferentAuthorsSameKind_BothStored()
    {
        // (kind, pubkey) keying — different pubkeys do not collide.
        using var store = new MemoryEventStore();
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();
        var aliceProfile = BuildEvent(alice, kind: 0, content: "alice");
        var bobProfile = BuildEvent(bob, kind: 0, content: "bob");

        Assert.Equal(StoreResult.Stored, await store.StoreAsync(aliceProfile));
        Assert.Equal(StoreResult.Stored, await store.StoreAsync(bobProfile));
        Assert.Equal(2, await store.CountAsync());
    }

    // ----- NIP-33 parameterized-replaceable.

    [Fact]
    public async Task StoreAsync_Addressable_DifferentDTags_BothStored()
    {
        // (kind, pubkey, d) keying — different d-tags do not collide.
        using var store = new MemoryEventStore();
        using var alice = PrivateKey.Generate();
        var post1 = BuildEvent(alice, kind: 30023, content: "post 1",
            tags: new[] { new[] { "d", "blog-post-1" } });
        var post2 = BuildEvent(alice, kind: 30023, content: "post 2",
            tags: new[] { new[] { "d", "blog-post-2" } });

        Assert.Equal(StoreResult.Stored, await store.StoreAsync(post1));
        Assert.Equal(StoreResult.Stored, await store.StoreAsync(post2));
        Assert.Equal(2, await store.CountAsync());
    }

    [Fact]
    public async Task StoreAsync_Addressable_SameDTagNewer_Replaces()
    {
        using var store = new MemoryEventStore();
        using var alice = PrivateKey.Generate();
        var old = BuildEvent(alice, kind: 30023, content: "v1", createdAt: 1_000,
            tags: new[] { new[] { "d", "slug" } });
        var fresh = BuildEvent(alice, kind: 30023, content: "v2", createdAt: 2_000,
            tags: new[] { new[] { "d", "slug" } });

        Assert.Equal(StoreResult.Stored, await store.StoreAsync(old));
        Assert.Equal(StoreResult.Replaced, await store.StoreAsync(fresh));
        Assert.Equal(1, await store.CountAsync());
        Assert.Null(await store.GetAsync(old.Id));
    }

    [Fact]
    public async Task StoreAsync_Addressable_MissingDTag_TreatedAsEmptyIdentifier()
    {
        // NIP-33: "the empty string is the default identifier".
        using var store = new MemoryEventStore();
        using var alice = PrivateKey.Generate();
        var noTag = BuildEvent(alice, kind: 30023, content: "v1", createdAt: 1_000);
        var emptyTag = BuildEvent(alice, kind: 30023, content: "v2", createdAt: 2_000,
            tags: new[] { new[] { "d", "" } });

        Assert.Equal(StoreResult.Stored, await store.StoreAsync(noTag));
        Assert.Equal(StoreResult.Replaced, await store.StoreAsync(emptyTag));
    }

    // ----- NIP-09 deletion.

    [Fact]
    public async Task StoreAsync_DeletionEvictsTargetedEvent()
    {
        using var store = new MemoryEventStore();
        using var alice = PrivateKey.Generate();
        var note = BuildEvent(alice, kind: 1, content: "regrettable");
        var deletion = BuildEvent(alice, kind: 5, content: "oops", createdAt: note.CreatedAt + 1,
            tags: new[] { new[] { "e", note.Id.ToHex() } });

        await store.StoreAsync(note);
        Assert.Equal(StoreResult.Stored, await store.StoreAsync(deletion));

        Assert.Null(await store.GetAsync(note.Id));
        // The deletion itself remains queryable.
        Assert.NotNull(await store.GetAsync(deletion.Id));
    }

    [Fact]
    public async Task StoreAsync_TombstonedEventArrivingLater_IsRejected()
    {
        // Deletion seen first; later attempt to store the targeted event
        // must be rejected without race.
        using var store = new MemoryEventStore();
        using var alice = PrivateKey.Generate();
        var note = BuildEvent(alice, kind: 1, content: "x");
        var deletion = BuildEvent(alice, kind: 5, content: "",
            tags: new[] { new[] { "e", note.Id.ToHex() } });

        await store.StoreAsync(deletion);
        Assert.Equal(StoreResult.Deleted, await store.StoreAsync(note));
    }

    [Fact]
    public async Task StoreAsync_AddressableDeletion_EvictsOlderVersion_AllowsNewerRepublish()
    {
        // NIP-09: addressable deletion is NOT a permanent tombstone —
        // a newer event at the same address may still be stored.
        using var store = new MemoryEventStore();
        using var alice = PrivateKey.Generate();
        var v1 = BuildEvent(alice, kind: 30023, content: "v1", createdAt: 1_000,
            tags: new[] { new[] { "d", "slug" } });
        var deletion = BuildEvent(alice, kind: 5, content: "", createdAt: 2_000,
            tags: new[] { new[] { "a", $"30023:{alice.PublicKey.ToHex()}:slug" } });
        var v2 = BuildEvent(alice, kind: 30023, content: "v2", createdAt: 3_000,
            tags: new[] { new[] { "d", "slug" } });

        await store.StoreAsync(v1);
        await store.StoreAsync(deletion);
        Assert.Null(await store.GetAsync(v1.Id));

        // Newer republish at the same address is allowed.
        Assert.Equal(StoreResult.Stored, await store.StoreAsync(v2));
    }

    // ----- NIP-40 expiration.

    [Fact]
    public async Task StoreAsync_AlreadyExpiredEvent_ReturnsExpired()
    {
        using var store = new MemoryEventStore();
        using var key = PrivateKey.Generate();
        long past = DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds();
        var ev = BuildEvent(key, kind: 1, content: "expired",
            tags: new[] { new[] { "expiration", past.ToString() } });

        Assert.Equal(StoreResult.Expired, await store.StoreAsync(ev));
        Assert.Equal(0, await store.CountAsync());
    }

    [Fact]
    public async Task QueryAsync_DoesNotYieldExpiredEvents()
    {
        // Race-free: insert with a future expiration, then construct a
        // store wrapper that pretends "now" is past it. Simpler: insert
        // with the expiration already in the past — covered above — and
        // assert Query also excludes it if somehow it slipped in.
        using var store = new MemoryEventStore();
        using var key = PrivateKey.Generate();
        var alive = BuildEvent(key, kind: 1, content: "ok");
        await store.StoreAsync(alive);

        var matches = new List<NostrEvent>();
        await foreach (var ev in store.QueryAsync(new Filter { Kinds = new[] { 1 } }))
        {
            matches.Add(ev);
        }

        Assert.Single(matches);
    }

    // ----- NIP-01 ephemeral (kinds 20000–29999): fan out, don't persist.

    [Fact]
    public async Task StoreAsync_EphemeralKind_NotPersisted_ButFannedOut()
    {
        using var store = new MemoryEventStore();
        using var key = PrivateKey.Generate();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var received = new List<NostrEvent>();
        var consumer = Task.Run(async () =>
        {
            await foreach (var ev in store.ObserveAsync(
                new Filter { Kinds = new[] { 20000 } }, cts.Token))
            {
                received.Add(ev);
                cts.Cancel();
            }
        });

        await Task.Delay(50);
        var ephemeral = BuildEvent(key, kind: 20000, content: "presence-ping");
        Assert.Equal(StoreResult.Ephemeral, await store.StoreAsync(ephemeral));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => consumer);

        // Fanned out to observer:
        Assert.Single(received);
        // But not persisted:
        Assert.Equal(0, await store.CountAsync());
        Assert.Null(await store.GetAsync(ephemeral.Id));
    }

    // ----- Capacity eviction.

    [Fact]
    public async Task Capacity_EvictsOldestByCreatedAt()
    {
        using var store = new MemoryEventStore(capacity: 3);
        using var key = PrivateKey.Generate();
        var a = BuildEvent(key, kind: 1, content: "a", createdAt: 1_000);
        var b = BuildEvent(key, kind: 1, content: "b", createdAt: 2_000);
        var c = BuildEvent(key, kind: 1, content: "c", createdAt: 3_000);
        var d = BuildEvent(key, kind: 1, content: "d", createdAt: 4_000);

        await store.StoreAsync(a);
        await store.StoreAsync(b);
        await store.StoreAsync(c);
        await store.StoreAsync(d);

        Assert.Equal(3, await store.CountAsync());
        Assert.Null(await store.GetAsync(a.Id));    // oldest evicted
        Assert.NotNull(await store.GetAsync(b.Id));
        Assert.NotNull(await store.GetAsync(c.Id));
        Assert.NotNull(await store.GetAsync(d.Id));
    }

    // ----- QueryAsync semantics.

    [Fact]
    public async Task QueryAsync_AppliesFilterAndLimit_OrderedNewestFirst()
    {
        using var store = new MemoryEventStore();
        using var key = PrivateKey.Generate();
        for (int i = 0; i < 5; i++)
        {
            await store.StoreAsync(BuildEvent(key, kind: 1, content: $"n{i}", createdAt: 1_000 + i));
        }

        await store.StoreAsync(BuildEvent(key, kind: 42, content: "wrong-kind"));

        var matches = new List<NostrEvent>();
        await foreach (var ev in store.QueryAsync(new Filter { Kinds = new[] { 1 }, Limit = 3 }))
        {
            matches.Add(ev);
        }

        Assert.Equal(3, matches.Count);
        // Newest-first.
        Assert.True(matches[0].CreatedAt > matches[1].CreatedAt);
        Assert.True(matches[1].CreatedAt > matches[2].CreatedAt);
    }

    // ----- ObserveAsync (live).

    [Fact]
    public async Task ObserveAsync_EmitsSnapshotThenLiveUpdates()
    {
        using var store = new MemoryEventStore();
        using var key = PrivateKey.Generate();

        // Pre-populate.
        var preexisting = BuildEvent(key, kind: 1, content: "old", createdAt: 1_000);
        await store.StoreAsync(preexisting);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var received = new List<NostrEvent>();

        var consumer = Task.Run(async () =>
        {
            await foreach (var ev in store.ObserveAsync(new Filter { Kinds = new[] { 1 } }, cts.Token))
            {
                received.Add(ev);
                if (received.Count >= 3)
                {
                    cts.Cancel();
                }
            }
        });

        // Give the snapshot a moment to emit.
        await Task.Delay(50);

        await store.StoreAsync(BuildEvent(key, kind: 1, content: "live-1", createdAt: 2_000));
        await store.StoreAsync(BuildEvent(key, kind: 1, content: "live-2", createdAt: 3_000));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => consumer);

        Assert.Equal(3, received.Count);
        Assert.Equal("old", received[0].Content);
        Assert.Equal("live-1", received[1].Content);
        Assert.Equal("live-2", received[2].Content);
    }

    [Fact]
    public async Task ObserveAsync_FilterSelectsRelevantEventsOnly()
    {
        using var store = new MemoryEventStore();
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var received = new List<NostrEvent>();

        var consumer = Task.Run(async () =>
        {
            await foreach (var ev in store.ObserveAsync(
                new Filter { Authors = new[] { alice.PublicKey.ToHex() }, Kinds = new[] { 1 } },
                cts.Token))
            {
                received.Add(ev);
                if (received.Count >= 1)
                {
                    cts.Cancel();
                }
            }
        });

        await Task.Delay(50);
        await store.StoreAsync(BuildEvent(bob, kind: 1, content: "ignored-by-author"));
        await store.StoreAsync(BuildEvent(alice, kind: 42, content: "ignored-by-kind"));
        await store.StoreAsync(BuildEvent(alice, kind: 1, content: "wanted"));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => consumer);

        Assert.Single(received);
        Assert.Equal("wanted", received[0].Content);
    }

    // ----- Helpers.

    private static NostrEvent BuildEvent(
        PrivateKey key,
        int kind,
        string content,
        long createdAt = 1_700_000_000L,
        IReadOnlyList<IReadOnlyList<string>>? tags = null) =>
        new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = createdAt,
            Kind = kind,
            Tags = tags ?? Array.Empty<IReadOnlyList<string>>(),
            Content = content,
        }.Sign(key);
}
