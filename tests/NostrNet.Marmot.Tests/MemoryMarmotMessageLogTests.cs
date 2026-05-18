// SPDX-License-Identifier: MIT

using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Marmot;

namespace NostrNet.Marmot.Tests;

public class MemoryMarmotMessageLogTests
{
    private static readonly byte[] GroupA = MakeGroupId(0xAA);
    private static readonly byte[] GroupB = MakeGroupId(0xBB);

    [Fact]
    public async Task Append_RoundTripsAndOrdersByTimestamp()
    {
        var log = new MemoryMarmotMessageLog();
        var conv = MakeConversation(GroupA);

        await log.AppendAsync(MakeMessage(conv, eventByte: 1, sec: 100, text: "first"));
        await log.AppendAsync(MakeMessage(conv, eventByte: 3, sec: 300, text: "third"));
        await log.AppendAsync(MakeMessage(conv, eventByte: 2, sec: 200, text: "second"));

        var loaded = new List<MarmotMessageReceived>();
        await foreach (var m in log.LoadAsync(GroupA))
        {
            loaded.Add(m);
        }

        Assert.Equal(new[] { "first", "second", "third" }, loaded.Select(m => m.Plaintext));
    }

    [Fact]
    public async Task Append_DedupsOnEventId()
    {
        var log = new MemoryMarmotMessageLog();
        var conv = MakeConversation(GroupA);

        var msg = MakeMessage(conv, eventByte: 7, sec: 100, text: "from relay A");
        var dup = MakeMessage(conv, eventByte: 7, sec: 100, text: "from relay B (same event id)");

        await log.AppendAsync(msg);
        await log.AppendAsync(dup);

        int count = 0;
        await foreach (var _ in log.LoadAsync(GroupA))
        {
            count++;
        }

        Assert.Equal(1, count);
    }

    [Fact]
    public async Task LoadAsync_FiltersBySinceAndLimit()
    {
        var log = new MemoryMarmotMessageLog();
        var conv = MakeConversation(GroupA);

        for (int i = 0; i < 5; i++)
        {
            await log.AppendAsync(MakeMessage(conv, eventByte: (byte)(i + 1), sec: 100 + i, text: $"msg-{i}"));
        }

        var filtered = new List<string>();
        await foreach (var m in log.LoadAsync(GroupA, since: DateTimeOffset.FromUnixTimeSeconds(102), limit: 2))
        {
            filtered.Add(m.Plaintext);
        }

        Assert.Equal(new[] { "msg-2", "msg-3" }, filtered);
    }

    [Fact]
    public async Task GetLastAsync_ReturnsNewest()
    {
        var log = new MemoryMarmotMessageLog();
        var conv = MakeConversation(GroupA);

        await log.AppendAsync(MakeMessage(conv, eventByte: 1, sec: 100, text: "old"));
        await log.AppendAsync(MakeMessage(conv, eventByte: 2, sec: 200, text: "new"));

        var last = await log.GetLastAsync(GroupA);
        Assert.NotNull(last);
        Assert.Equal("new", last!.Plaintext);
    }

    [Fact]
    public async Task GetLastAsync_NullForEmptyGroup()
    {
        var log = new MemoryMarmotMessageLog();
        Assert.Null(await log.GetLastAsync(GroupA));
    }

    [Fact]
    public async Task DeleteGroupAsync_ClearsHistoryAndPermitsReinsert()
    {
        var log = new MemoryMarmotMessageLog();
        var conv = MakeConversation(GroupA);

        var msg = MakeMessage(conv, eventByte: 9, sec: 500, text: "before delete");
        await log.AppendAsync(msg);
        Assert.NotNull(await log.GetLastAsync(GroupA));

        await log.DeleteGroupAsync(GroupA);
        Assert.Null(await log.GetLastAsync(GroupA));

        // Dedup state for the group should also be cleared — re-append works.
        await log.AppendAsync(msg);
        Assert.NotNull(await log.GetLastAsync(GroupA));
    }

    [Fact]
    public async Task PerGroupIsolation()
    {
        var log = new MemoryMarmotMessageLog();
        var convA = MakeConversation(GroupA);
        var convB = MakeConversation(GroupB);

        await log.AppendAsync(MakeMessage(convA, eventByte: 1, sec: 100, text: "in A"));
        await log.AppendAsync(MakeMessage(convB, eventByte: 1, sec: 100, text: "in B"));

        Assert.Equal("in A", (await log.GetLastAsync(GroupA))?.Plaintext);
        Assert.Equal("in B", (await log.GetLastAsync(GroupB))?.Plaintext);

        await log.DeleteGroupAsync(GroupA);
        Assert.Null(await log.GetLastAsync(GroupA));
        Assert.NotNull(await log.GetLastAsync(GroupB));   // B untouched
    }

    private static MarmotConversation MakeConversation(byte[] groupId) =>
        new(groupId, Peer: null);

    private static MarmotMessageReceived MakeMessage(MarmotConversation conv, byte eventByte, long sec, string text)
    {
        var idBytes = new byte[EventId.Size];
        idBytes[0] = eventByte;
        var eventId = new EventId(idBytes);

        return new MarmotMessageReceived(
            Conversation: conv,
            EventId: eventId,
            RumorId: eventId,
            RumorKind: MarmotChat.ChatMessageRumorKind,
            RumorTags: Array.Empty<IReadOnlyList<string>>(),
            Sender: null,
            Plaintext: text,
            ServerTimestamp: DateTimeOffset.FromUnixTimeSeconds(sec));
    }

    private static byte[] MakeGroupId(byte seed)
    {
        var g = new byte[32];
        for (int i = 0; i < g.Length; i++)
        {
            g[i] = seed;
        }

        return g;
    }
}
