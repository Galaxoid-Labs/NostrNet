// SPDX-License-Identifier: MIT
//
// Tests for the NIP-11 relay information document parser and URL conversion.

using NostrNet.Relay;

namespace NostrNet.Tests.Relay;

public class RelayInformationTests
{
    // A representative NIP-11 document hitting most documented fields.
    private const string SampleJson = """
    {
      "name": "Example Relay",
      "description": "A relay for testing.",
      "banner": "https://example.com/banner.png",
      "icon": "https://example.com/icon.png",
      "pubkey": "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
      "self": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      "contact": "mailto:admin@example.com",
      "supported_nips": [1, 11, 13, 17, 44, 59],
      "software": "https://github.com/example/relay",
      "version": "1.2.3",
      "privacy_policy": "https://example.com/privacy",
      "terms_of_service": "https://example.com/tos",
      "posting_policy": "https://example.com/posting",
      "payments_url": "https://example.com/pay",
      "limitation": {
        "max_message_length": 16384,
        "max_subscriptions": 20,
        "max_filters": 100,
        "max_limit": 5000,
        "default_limit": 500,
        "max_subid_length": 100,
        "max_event_tags": 100,
        "max_content_length": 8196,
        "min_pow_difficulty": 0,
        "auth_required": false,
        "payment_required": false,
        "restricted_writes": false,
        "created_at_lower_limit": 1640995200,
        "created_at_upper_limit": 9999999999
      },
      "fees": {
        "admission": [{ "amount": 1000000, "unit": "msats" }],
        "subscription": [{ "amount": 5000, "unit": "msats", "period": 2592000 }],
        "publication": [{ "amount": 100, "unit": "msats", "kinds": [4, 9735] }]
      },
      "relay_countries": ["us", "de"],
      "language_tags": ["en", "de"],
      "tags": ["bitcoin", "freedomtech"],
      "unknown_future_field": "ignored"
    }
    """;

    [Fact]
    public void Parse_AllFieldsPopulated()
    {
        var info = RelayInformation.Parse(SampleJson);

        Assert.Equal("Example Relay", info.Name);
        Assert.Equal("A relay for testing.", info.Description);
        Assert.Equal("https://example.com/banner.png", info.Banner);
        Assert.Equal("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d", info.Pubkey);
        Assert.Equal("mailto:admin@example.com", info.Contact);
        Assert.Equal(new[] { 1, 11, 13, 17, 44, 59 }, info.SupportedNips);
        Assert.Equal("1.2.3", info.Version);
        Assert.Equal("https://example.com/posting", info.PostingPolicy);
        Assert.Equal("https://example.com/pay", info.PaymentsUrl);
    }

    [Fact]
    public void Parse_LimitationFields()
    {
        var info = RelayInformation.Parse(SampleJson);
        var lim = info.Limitation;

        Assert.NotNull(lim);
        Assert.Equal(16384, lim!.MaxMessageLength);
        Assert.Equal(20, lim.MaxSubscriptions);
        Assert.Equal(5000, lim.MaxLimit);
        Assert.Equal(500, lim.DefaultLimit);
        Assert.Equal(0, lim.MinPowDifficulty);
        Assert.False(lim.AuthRequired);
        Assert.False(lim.PaymentRequired);
        Assert.Equal(1640995200, lim.CreatedAtLowerLimit);
    }

    [Fact]
    public void Parse_FeesFields()
    {
        var info = RelayInformation.Parse(SampleJson);
        var fees = info.Fees;

        Assert.NotNull(fees);
        Assert.NotNull(fees!.Admission);
        Assert.Single(fees.Admission!);
        Assert.Equal(1_000_000L, fees.Admission![0].Amount);
        Assert.Equal("msats", fees.Admission[0].Unit);

        Assert.NotNull(fees.Subscription);
        Assert.Equal(2_592_000, fees.Subscription![0].Period);

        Assert.NotNull(fees.Publication);
        Assert.Equal(new[] { 4, 9735 }, fees.Publication![0].Kinds);
    }

    [Fact]
    public void Parse_MinimalDocument_LeavesAllNull()
    {
        var info = RelayInformation.Parse("{}");
        Assert.Null(info.Name);
        Assert.Null(info.SupportedNips);
        Assert.Null(info.Limitation);
        Assert.Null(info.Fees);
    }

    [Fact]
    public void Parse_UnknownFieldsIgnored()
    {
        // The sample includes "unknown_future_field"; parsing must succeed.
        var info = RelayInformation.Parse(SampleJson);
        Assert.Equal("Example Relay", info.Name);
    }

    [Fact]
    public void SupportsNip_TrueWhenPresent()
    {
        var info = RelayInformation.Parse(SampleJson);
        Assert.True(info.SupportsNip(11));
        Assert.True(info.SupportsNip(44));
        Assert.False(info.SupportsNip(7));
    }

    [Fact]
    public void SupportsSearch_ReflectsNip50InSupportedNips()
    {
        var with50 = RelayInformation.Parse("""{"supported_nips":[1,50]}""");
        Assert.True(with50.SupportsSearch);

        var without50 = RelayInformation.Parse("""{"supported_nips":[1,11,42]}""");
        Assert.False(without50.SupportsSearch);

        var noNipsAtAll = RelayInformation.Parse("""{"name":"x"}""");
        Assert.False(noNipsAtAll.SupportsSearch);
    }

    [Fact]
    public void SupportsNip_FalseWhenListAbsent()
    {
        var info = RelayInformation.Parse("{}");
        Assert.False(info.SupportsNip(1));
    }

    // ----- Scheme rewriting.

    [Theory]
    [InlineData("wss://relay.example.com", "https://relay.example.com/")]
    [InlineData("ws://relay.example.com", "http://relay.example.com/")]
    [InlineData("https://relay.example.com", "https://relay.example.com/")]
    [InlineData("http://relay.example.com", "http://relay.example.com/")]
    [InlineData("wss://relay.example.com:8443/path", "https://relay.example.com:8443/path")]
    [InlineData("wss://relay.example.com:443", "https://relay.example.com/")]   // default port stripped
    [InlineData("ws://relay.example.com:80", "http://relay.example.com/")]      // default port stripped
    public void ToHttpUri_RewritesScheme(string input, string expected)
    {
        var rewritten = RelayInformation.ToHttpUri(new Uri(input));
        Assert.Equal(expected, rewritten.ToString());
    }

    [Theory]
    [InlineData("ftp://relay.example.com")]
    [InlineData("file:///etc/passwd")]
    public void ToHttpUri_RejectsUnsupportedScheme(string input)
    {
        Assert.Throws<ArgumentException>(() => RelayInformation.ToHttpUri(new Uri(input)));
    }
}
