// SPDX-License-Identifier: MIT
//
// Tests for the relay-protocol parser and builder. Validates the JSON shapes
// that go on the wire in either direction.

using NostrNet.Events;
using NostrNet.Relay;

namespace NostrNet.Tests.Relay;

public class RelayProtocolTests
{
    private const string KnownEventJson =
        """
        {"id":"f603166e0fdb6a0329e3998280ecad0e54d89f5f8bc20d1f259a41983aca9dfb","pubkey":"3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d","created_at":1711372078,"kind":1,"tags":[["client","gossip"],["p","fd5989ddfadd9e2af6ceb8b63942a9e31b37367e89917931ede3b2ea76823f10"],["e","7eb018629bcea71512ac83a8b5dab73fa0484c395eafeff797ace4ec463fee7f","wss://nostr.wine/","root"],["e","ab1f4ebf1f75c7bdff65e95bbd068775b5623fedf9be1b0903cbc0b47e1d1c4d","wss://nostr.mom/","reply"]],"content":"Damn, this is frightening.\n\nWhy are early 2000s articles flagged as AI?","sig":"09c197c5159eeac3213fdadec5245501df617a23a5f9b581db22ee822a10f98509302a50335166bd24f672ec19c945e0048bedf25497e53161b80b9e67a1d941"}
        """;

    [Fact]
    public void Parse_EventMessage()
    {
        string wire = $"""["EVENT","sub1",{KnownEventJson}]""";
        var msg = RelayMessage.Parse(wire);
        var ev = Assert.IsType<EventMessage>(msg);
        Assert.Equal("sub1", ev.SubscriptionId);
        Assert.Equal("f603166e0fdb6a0329e3998280ecad0e54d89f5f8bc20d1f259a41983aca9dfb", ev.Event.Id.ToHex());
        Assert.True(ev.Event.Verify());
    }

    [Fact]
    public void Parse_EoseMessage()
    {
        var msg = RelayMessage.Parse("""["EOSE","sub1"]""");
        var eose = Assert.IsType<EndOfStoredEventsMessage>(msg);
        Assert.Equal("sub1", eose.SubscriptionId);
    }

    [Fact]
    public void Parse_OkMessage_Accepted()
    {
        var msg = RelayMessage.Parse("""["OK","abc",true,""]""");
        var ok = Assert.IsType<OkMessage>(msg);
        Assert.Equal("abc", ok.EventId);
        Assert.True(ok.Accepted);
        Assert.Equal(string.Empty, ok.Message);
    }

    [Fact]
    public void Parse_OkMessage_Rejected()
    {
        var msg = RelayMessage.Parse("""["OK","abc",false,"blocked: pubkey blocked"]""");
        var ok = Assert.IsType<OkMessage>(msg);
        Assert.False(ok.Accepted);
        Assert.Equal("blocked: pubkey blocked", ok.Message);
    }

    [Fact]
    public void Parse_NoticeMessage()
    {
        var msg = RelayMessage.Parse("""["NOTICE","slow down"]""");
        var notice = Assert.IsType<NoticeMessage>(msg);
        Assert.Equal("slow down", notice.Message);
    }

    [Fact]
    public void Parse_ClosedMessage()
    {
        var msg = RelayMessage.Parse("""["CLOSED","sub1","auth-required: please authenticate"]""");
        var closed = Assert.IsType<ClosedMessage>(msg);
        Assert.Equal("sub1", closed.SubscriptionId);
        Assert.Contains("auth-required", closed.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_AuthChallengeMessage()
    {
        var msg = RelayMessage.Parse("""["AUTH","challengestring"]""");
        var auth = Assert.IsType<AuthChallengeMessage>(msg);
        Assert.Equal("challengestring", auth.Challenge);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{}")]                    // object, not array
    [InlineData("[]")]                    // empty array
    [InlineData("""["FROBNICATE"]""")]    // unknown tag
    public void Parse_RejectsInvalid(string wire)
    {
        Assert.Throws<FormatException>(() => RelayMessage.Parse(wire));
    }

    // ----- Outgoing builders.

    [Fact]
    public void BuildSubscribeMessage_IncludesFilters()
    {
        string wire = RelayProtocol.BuildSubscribeMessage("subA", new[]
        {
            Filter.ByKinds(1) with { Limit = 5 },
        });
        Assert.StartsWith("""["REQ","subA",{""", wire, StringComparison.Ordinal);
        Assert.Contains("\"kinds\":[1]", wire, StringComparison.Ordinal);
        Assert.Contains("\"limit\":5", wire, StringComparison.Ordinal);
        Assert.EndsWith("}]", wire, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildCloseMessage_ProducesCloseEnvelope()
    {
        string wire = RelayProtocol.BuildCloseMessage("subA");
        Assert.Equal("""["CLOSE","subA"]""", wire);
    }

    [Fact]
    public void BuildPublishMessage_WrapsEventJson()
    {
        var ev = NostrEvent.FromJson(KnownEventJson);
        string wire = RelayProtocol.BuildPublishMessage(ev);
        Assert.StartsWith("""["EVENT",{""", wire, StringComparison.Ordinal);
        Assert.EndsWith("}]", wire, StringComparison.Ordinal);

        // Re-parse via RelayMessage to verify symmetry.
        // The protocol incoming form is ["EVENT", subId, evJson]; here we have ["EVENT", evJson].
        // We can re-parse the inner event to confirm round-trip fidelity.
        int firstBrace = wire.IndexOf('{');
        int lastBrace = wire.LastIndexOf('}');
        string innerJson = wire.Substring(firstBrace, lastBrace - firstBrace + 1);
        var rt = NostrEvent.FromJson(innerJson);
        Assert.Equal(ev.Id, rt.Id);
        Assert.True(rt.Verify());
    }
}
