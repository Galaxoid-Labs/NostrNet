// SPDX-License-Identifier: MIT
//
// Coverage for the generic typed accessors on INostrEventStore.
// Verifies that:
//   - Default Kinds (from T.Kinds) gets applied when filter.Kinds is null
//   - Caller-supplied Kinds is respected (narrowing within T.Kinds)
//   - Events that fail T.TryFromEvent are silently skipped
//   - ObserveAsync<T> emits snapshot + live updates as the store grows
//   - GetAsync<T> returns null when the event isn't there OR doesn't match T

using NostrNet.Articles;
using NostrNet.Client.Storage;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Profiles;
using NostrNet.Relay;
using NostrNet.Relay.Storage;

namespace NostrNet.Client.Tests.Storage;

public class TypedStoreExtensionsTests
{
    [Fact]
    public async Task QueryAsync_T_DefaultsKindsToTKinds()
    {
        using var store = new MemoryEventStore();
        using var alice = PrivateKey.Generate();

        await store.StoreAsync(BuildKind0(alice, "alice"));
        await store.StoreAsync(BuildNote(alice, "ignored note"));

        var profiles = new List<Profile>();
        await foreach (var profile in store.QueryAsync<Profile>())
        {
            profiles.Add(profile);
        }

        // Only kind-0 considered; the note was filtered out by T.Kinds.
        Assert.Single(profiles);
        Assert.Equal(alice.PublicKey, profiles[0].Owner);
        Assert.Equal("alice", profiles[0].Name);
    }

    [Fact]
    public async Task QueryAsync_T_RespectsCallerKindsWhenSupplied()
    {
        // Article.Kinds = [30023, 30024]. Caller narrows to 30023 only.
        using var store = new MemoryEventStore();
        using var alice = PrivateKey.Generate();

        await store.StoreAsync(BuildArticle(alice, kind: 30023, slug: "published"));
        await store.StoreAsync(BuildArticle(alice, kind: 30024, slug: "draft"));

        var published = new List<Article>();
        await foreach (var article in store.QueryAsync<Article>(
            new Filter { Kinds = new[] { 30023 } }))
        {
            published.Add(article);
        }

        Assert.Single(published);
        Assert.Equal("published", published[0].Identifier);
    }

    [Fact]
    public async Task QueryAsync_T_SkipsEventsThatFailTryFromEvent()
    {
        using var store = new MemoryEventStore();
        using var alice = PrivateKey.Generate();

        // A regular kind-0 (parses fine)
        await store.StoreAsync(BuildKind0(alice, "alice"));
        // A kind-0 with content that's not valid JSON
        await store.StoreAsync(BuildEvent(alice, kind: 0, content: "not valid json {{"));

        var profiles = new List<Profile>();
        await foreach (var p in store.QueryAsync<Profile>())
        {
            profiles.Add(p);
        }

        // Only the well-formed one — Profile.TryFromEvent rejects the malformed one.
        Assert.Single(profiles);
    }

    [Fact]
    public async Task ObserveAsync_T_EmitsSnapshotThenLive()
    {
        using var store = new MemoryEventStore();
        using var alice = PrivateKey.Generate();
        using var bob = PrivateKey.Generate();

        await store.StoreAsync(BuildKind0(alice, "alice"));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var received = new List<Profile>();
        var consumer = Task.Run(async () =>
        {
            await foreach (var profile in store.ObserveAsync<Profile>(cancellationToken: cts.Token))
            {
                received.Add(profile);
                if (received.Count >= 2)
                {
                    cts.Cancel();
                }
            }
        });

        await Task.Delay(50);
        await store.StoreAsync(BuildKind0(bob, "bob"));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => consumer);

        Assert.Equal(2, received.Count);
        Assert.Equal("alice", received[0].Name);
        Assert.Equal("bob", received[1].Name);
    }

    [Fact]
    public async Task GetAsync_T_ReturnsNullWhenIdMissing()
    {
        using var store = new MemoryEventStore();
        using var alice = PrivateKey.Generate();
        var missingId = BuildKind0(alice, "alice").Id;   // generate then don't store

        var result = await store.GetAsync<Profile>(missingId);
        Assert.Null(result);
    }

    [Fact]
    public async Task GetAsync_T_ReturnsNullWhenEventDoesNotMatchType()
    {
        using var store = new MemoryEventStore();
        using var alice = PrivateKey.Generate();
        var note = BuildNote(alice, "just a note");
        await store.StoreAsync(note);

        // The id IS in the store, but it's a kind-1 note — not a Profile.
        var result = await store.GetAsync<Profile>(note.Id);
        Assert.Null(result);
    }

    [Fact]
    public async Task GetAsync_T_ReturnsTypedValueWhenMatches()
    {
        using var store = new MemoryEventStore();
        using var alice = PrivateKey.Generate();
        var ev = BuildKind0(alice, "alice");
        await store.StoreAsync(ev);

        var result = await store.GetAsync<Profile>(ev.Id);
        Assert.NotNull(result);
        Assert.Equal("alice", result.Name);
    }

    // ----- Helpers.

    private static NostrEvent BuildKind0(PrivateKey key, string name) =>
        BuildEvent(key, kind: 0, content: "{\"name\":\"" + name + "\"}");

    private static NostrEvent BuildNote(PrivateKey key, string content) =>
        BuildEvent(key, kind: 1, content: content);

    private static NostrEvent BuildArticle(PrivateKey key, int kind, string slug) =>
        new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = kind,
            Tags = new IReadOnlyList<string>[]
            {
                new[] { "d", slug },
                new[] { "title", slug },
            },
            Content = "body",
        }.Sign(key);

    private static NostrEvent BuildEvent(PrivateKey key, int kind, string content) =>
        new UnsignedEvent
        {
            PubKey = key.PublicKey,
            CreatedAt = 1_700_000_000L,
            Kind = kind,
            Tags = Array.Empty<IReadOnlyList<string>>(),
            Content = content,
        }.Sign(key);
}
