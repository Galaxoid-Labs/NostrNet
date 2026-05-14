// SPDX-License-Identifier: MIT
//
// NostrNet sample app.
//
// Demonstrates:
//   1. Generating or loading a keypair (nsec).
//   2. Connecting to one or more relays.
//   3. Posting a text note.
//   4. Sending a NIP-17 direct message.
//   5. Subscribing to your own feed and (briefly) listening for DMs.
//
// Usage:
//   dotnet run --project samples/NostrNet.Sample.Console -- <command> [args]
//
// Commands:
//   gen                                  — generate a fresh nsec/npub pair
//   post <nsec> <text>                   — publish a kind-1 note
//   dm   <nsec> <recipient-npub> <text>  — send a NIP-17 DM
//   feed <nsec> [--seconds N]            — subscribe to your kind-1 posts for N s
//   mine <nsec> <text> <difficulty>      — mine a NIP-13 kind-1 note and publish
//   info <relay-uri>                     — fetch the relay's NIP-11 document
//   verify <npub> <identifier>           — NIP-05 verify a pubkey ↔ identifier mapping
//   vanity-pow <bits>                    — generate a key with N leading-zero pubkey bits
//   vanity-npub <pattern> [--suffix]     — generate a key whose npub matches a bech32 pattern
//   vanity-hex  <pattern> [--suffix]     — generate a key whose pubkey hex matches a pattern

using NostrNet.Client;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Marmot;
using NostrNet.Marmot.Mls.Reference;
using NostrNet.Relay;

string[] DefaultRelays =
{
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
};

if (args.Length == 0)
{
    PrintUsage();
    return 64;
}

try
{
    return args[0] switch
    {
        "gen" => Generate(),
        "post" => await PostAsync(args),
        "dm" => await SendDmAsync(args),
        "feed" => await ListenFeedAsync(args),
        "mine" => await MineAsync(args),
        "info" => await InfoAsync(args),
        "verify" => await VerifyNip05Async(args),
        "vanity-pow" => await VanityPowAsync(args),
        "vanity-npub" => await VanityAsync(args, npub: true),
        "vanity-hex" => await VanityAsync(args, npub: false),
        "marmot-mls-smoke" => await MarmotMlsSmokeAsync(),
        _ => UnknownCommand(args[0]),
    };
}
catch (Exception ex)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    return 1;
}

int Generate()
{
    using var key = PrivateKey.Generate();
    Console.WriteLine($"nsec: {key.ToNsec()}");
    Console.WriteLine($"npub: {key.PublicKey.ToNpub()}");
    return 0;
}

async Task<int> PostAsync(string[] argv)
{
    if (argv.Length < 3)
    {
        Console.Error.WriteLine("usage: post <nsec> <text>");
        return 64;
    }

    using var key = PrivateKey.FromNsec(argv[1]);
    string note = argv[2];

    await using var client = await NostrClient.Builder(key)
        .UseRelays(DefaultRelays)
        .ConnectAsync()
        .ConfigureAwait(false);

    Console.WriteLine($"posting as {key.PublicKey.ToNpub()} to {string.Join(", ", client.Relays)}...");
    var results = await client.PostNoteAsync(note).ConfigureAwait(false);
    foreach ((Uri uri, var r) in results)
    {
        Console.WriteLine($"  {uri}: {(r.Accepted ? "OK" : "REJECTED")} {r.Message}");
    }

    return results.Values.Any(r => r.Accepted) ? 0 : 2;
}

async Task<int> SendDmAsync(string[] argv)
{
    if (argv.Length < 4)
    {
        Console.Error.WriteLine("usage: dm <nsec> <recipient-npub> <text>");
        return 64;
    }

    using var key = PrivateKey.FromNsec(argv[1]);
    var recipient = PublicKey.FromNpub(argv[2]);
    string text = argv[3];

    await using var client = await NostrClient.Builder(key)
        .UseRelays(DefaultRelays)
        .ConnectAsync()
        .ConfigureAwait(false);

    Console.WriteLine($"sending NIP-17 DM to {recipient.ToNpub()}...");
    var results = await client.SendDirectMessageAsync(recipient, text).ConfigureAwait(false);
    foreach ((Uri uri, var r) in results)
    {
        Console.WriteLine($"  {uri}: {(r.Accepted ? "OK" : "REJECTED")} {r.Message}");
    }

    return results.Values.Any(r => r.Accepted) ? 0 : 2;
}

async Task<int> ListenFeedAsync(string[] argv)
{
    if (argv.Length < 2)
    {
        Console.Error.WriteLine("usage: feed <nsec> [--seconds N]");
        return 64;
    }

    using var key = PrivateKey.FromNsec(argv[1]);

    int seconds = 30;
    for (int i = 2; i < argv.Length - 1; i++)
    {
        if (argv[i] == "--seconds" && int.TryParse(argv[i + 1], out int parsed))
        {
            seconds = parsed;
        }
    }

    await using var client = await NostrClient.Builder(key)
        .UseRelays(DefaultRelays)
        .ConnectAsync()
        .ConfigureAwait(false);

    Console.WriteLine($"listening for kind-1 notes from {key.PublicKey.ToNpub()} for {seconds}s...");
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));

    try
    {
        await foreach (var received in client.SubscribeNotesAsync(
            authors: new[] { key.PublicKey },
            limit: 50,
            cancellationToken: cts.Token).ConfigureAwait(false))
        {
            var ev = received.Event;
            string preview = ev.Content.Length > 80 ? ev.Content[..77] + "..." : ev.Content;
            preview = preview.ReplaceLineEndings(" ");
            Console.WriteLine($"  [{received.Relay.Host}] {ev.CreatedAt}  {preview}");
        }
    }
    catch (OperationCanceledException)
    {
        // Timeout — expected.
    }

    return 0;
}

async Task<int> MineAsync(string[] argv)
{
    if (argv.Length < 4 || !int.TryParse(argv[3], out int difficulty))
    {
        Console.Error.WriteLine("usage: mine <nsec> <text> <difficulty>");
        return 64;
    }

    using var key = PrivateKey.FromNsec(argv[1]);
    string text = argv[2];

    var template = new UnsignedEvent
    {
        PubKey = key.PublicKey,
        CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        Kind = 1,
        Tags = Array.Empty<IReadOnlyList<string>>(),
        Content = text,
    };

    Console.WriteLine($"mining {difficulty}-bit PoW (may take a while)...");
    var sw = System.Diagnostics.Stopwatch.StartNew();
    var mined = ProofOfWork.Mine(template, difficulty);
    sw.Stop();
    var signed = mined.Sign(key);
    Console.WriteLine($"  id: {signed.Id.ToHex()}");
    Console.WriteLine($"  difficulty achieved: {ProofOfWork.Difficulty(signed)} bits  (in {sw.Elapsed.TotalSeconds:F1}s)");

    await using var client = await NostrClient.Builder(key)
        .UseRelays(DefaultRelays)
        .ConnectAsync()
        .ConfigureAwait(false);

    var results = await client.PublishAsync(signed).ConfigureAwait(false);
    foreach ((Uri uri, var r) in results)
    {
        Console.WriteLine($"  {uri}: {(r.Accepted ? "OK" : "REJECTED")} {r.Message}");
    }

    return results.Values.Any(r => r.Accepted) ? 0 : 2;
}

async Task<int> InfoAsync(string[] argv)
{
    if (argv.Length < 2)
    {
        Console.Error.WriteLine("usage: info <relay-uri>");
        return 64;
    }

    var info = await RelayInformation.FetchAsync(new Uri(argv[1])).ConfigureAwait(false);
    Console.WriteLine($"name:         {info.Name}");
    Console.WriteLine($"description:  {info.Description}");
    Console.WriteLine($"software:     {info.Software}");
    Console.WriteLine($"version:      {info.Version}");
    Console.WriteLine($"contact:      {info.Contact}");
    Console.WriteLine($"supported:    {string.Join(", ", info.SupportedNips ?? Array.Empty<int>())}");
    if (info.Limitation is { } lim)
    {
        Console.WriteLine($"limitation:");
        if (lim.MaxMessageLength is int mml) Console.WriteLine($"  max_message_length:  {mml}");
        if (lim.MaxSubscriptions is int msu) Console.WriteLine($"  max_subscriptions:   {msu}");
        if (lim.MaxLimit is int ml) Console.WriteLine($"  max_limit:           {ml}");
        if (lim.MinPowDifficulty is int mpw) Console.WriteLine($"  min_pow_difficulty:  {mpw}");
        if (lim.AuthRequired is bool ar) Console.WriteLine($"  auth_required:       {ar}");
        if (lim.PaymentRequired is bool pr) Console.WriteLine($"  payment_required:    {pr}");
    }

    return 0;
}

async Task<int> VerifyNip05Async(string[] argv)
{
    if (argv.Length < 3)
    {
        Console.Error.WriteLine("usage: verify <npub> <identifier>");
        return 64;
    }

    var pub = PublicKey.FromNpub(argv[1]);
    string identifier = argv[2];

    Console.WriteLine($"verifying {identifier} resolves to {pub.ToNpub()}...");
    var result = await Nip05.VerifyAsync(pub, identifier).ConfigureAwait(false);

    if (result.IsVerified)
    {
        Console.WriteLine("  VERIFIED");
        if (result.Relays.Count > 0)
        {
            Console.WriteLine($"  recommended relays: {string.Join(", ", result.Relays)}");
        }

        return 0;
    }

    Console.WriteLine($"  NOT VERIFIED: {result.FailureReason}");
    return 2;
}

async Task<int> VanityPowAsync(string[] argv)
{
    if (argv.Length < 2 || !int.TryParse(argv[1], out int bits))
    {
        Console.Error.WriteLine("usage: vanity-pow <bits>");
        return 64;
    }

    Console.WriteLine($"mining a key with {bits} leading-zero bits (Ctrl-C to stop)...");
    var (cts, progress) = SetupVanitySearch();

    try
    {
        using var key = await VanityKeyGenerator.MinePowAsync(bits, progress: progress, cancellationToken: cts.Token);
        Console.WriteLine();
        Console.WriteLine($"  nsec: {key.ToNsec()}");
        Console.WriteLine($"  npub: {key.PublicKey.ToNpub()}");
        Console.WriteLine($"  hex:  {key.PublicKey.ToHex()}");
        return 0;
    }
    catch (OperationCanceledException) { Console.WriteLine(); Console.WriteLine("cancelled."); return 130; }
}

async Task<int> VanityAsync(string[] argv, bool npub)
{
    if (argv.Length < 2)
    {
        Console.Error.WriteLine($"usage: vanity-{(npub ? "npub" : "hex")} <pattern> [--suffix]");
        return 64;
    }

    string pattern = argv[1];
    bool suffix = argv.Length > 2 && argv[2] == "--suffix";

    Console.WriteLine(
        $"mining a key whose {(npub ? "npub" : "pubkey hex")} {(suffix ? "ends with" : "starts with")} '{pattern}'...");
    var (cts, progress) = SetupVanitySearch();

    try
    {
        PrivateKey key;
        if (npub && !suffix)      key = await VanityKeyGenerator.MineNpubPrefixAsync(pattern, progress: progress, cancellationToken: cts.Token);
        else if (npub)            key = await VanityKeyGenerator.MineNpubSuffixAsync(pattern, progress: progress, cancellationToken: cts.Token);
        else if (!suffix)         key = await VanityKeyGenerator.MineHexPrefixAsync(pattern, progress: progress, cancellationToken: cts.Token);
        else                       key = await VanityKeyGenerator.MineHexSuffixAsync(pattern, progress: progress, cancellationToken: cts.Token);

        using (key)
        {
            Console.WriteLine();
            Console.WriteLine($"  nsec: {key.ToNsec()}");
            Console.WriteLine($"  npub: {key.PublicKey.ToNpub()}");
            Console.WriteLine($"  hex:  {key.PublicKey.ToHex()}");
        }

        return 0;
    }
    catch (OperationCanceledException) { Console.WriteLine(); Console.WriteLine("cancelled."); return 130; }
    catch (ArgumentException ex) { Console.Error.WriteLine($"error: {ex.Message}"); return 64; }
}

(CancellationTokenSource cts, IProgress<VanityMiningProgress> progress) SetupVanitySearch()
{
    var cancelSource = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { cancelSource.Cancel(); e.Cancel = true; };
    var progress = new Progress<VanityMiningProgress>(p =>
        Console.Write($"\r  attempts: {p.Attempts:N0}  rate: {p.AttemptsPerSecond:N0}/sec  elapsed: {p.Elapsed:mm\\:ss}   "));
    return (cancelSource, progress);
}

int UnknownCommand(string cmd)
{
    Console.Error.WriteLine($"unknown command: {cmd}");
    PrintUsage();
    return 64;
}

void PrintUsage()
{
    Console.Error.WriteLine("commands:");
    Console.Error.WriteLine("  gen                                  generate a fresh nsec/npub pair");
    Console.Error.WriteLine("  post  <nsec> <text>                  publish a kind-1 note");
    Console.Error.WriteLine("  dm    <nsec> <recipient-npub> <text> send a NIP-17 direct message");
    Console.Error.WriteLine("  feed  <nsec> [--seconds N]           subscribe to your own notes");
    Console.Error.WriteLine("  mine  <nsec> <text> <difficulty>     mine a NIP-13 PoW note and publish");
    Console.Error.WriteLine("  info  <relay-uri>                    fetch the relay's NIP-11 document");
    Console.Error.WriteLine("  verify <npub> <identifier>           NIP-05 verify pubkey ↔ identifier");
    Console.Error.WriteLine("  vanity-pow  <bits>                   mine a key with N leading-zero pubkey bits");
    Console.Error.WriteLine("  vanity-npub <pattern> [--suffix]     mine a key whose npub matches a bech32 pattern");
    Console.Error.WriteLine("  vanity-hex  <pattern> [--suffix]     mine a key whose pubkey hex matches a pattern");
    Console.Error.WriteLine("  marmot-mls-smoke                     experimental: in-tree MLS two-member round-trip smoke test");
}

// Drives the full Marmot + reference-MLS 1:1 chat flow end-to-end without
// touching the network. Useful both as a demo of the MarmotChat helper
// and as the AOT-publish smoke test for the BouncyCastle-backed MLS
// reference provider.
async Task<int> MarmotMlsSmokeAsync()
{
    using var aliceKey = PrivateKey.Generate();
    using var bobKey = PrivateKey.Generate();

    var aliceProv = new ReferenceMarmotMlsProvider();
    var bobProv = new ReferenceMarmotMlsProvider();
    var relays = new[] { "wss://relay.example" };

    // Bob publishes his KeyPackage event (kind-30443). In a real app this
    // would be sent to his inbox relays.
    var bobKpEvent = await MarmotChat.BuildKeyPackageEventAsync(
        bobProv, bobKey, slot: "default", relays);

    // Alice fetches Bob's KeyPackage off a relay (skipped here) and starts
    // a conversation. She gets a kind-1059 gift wrap to publish to Bob.
    var started = await MarmotChat.StartConversationAsync(
        aliceProv, aliceKey, bobKpEvent, "Alice <> Bob", relays);

    // Bob's app subscribes to kind-1059 gift wraps addressed to him, and
    // tries to accept each as a Marmot invite.
    var bobConvo = await MarmotChat.TryAcceptInviteAsync(bobProv, bobKey, started.WelcomeGiftWrap);
    if (bobConvo is null)
    {
        Console.Error.WriteLine("✗ bob failed to accept invite");
        return 1;
    }

    // Bidirectional ping-pong over the channel.
    var aliceToBob = await MarmotChat.EncryptMessageAsync(aliceProv, started.Conversation, "hello bob");
    string? gotByBob = await MarmotChat.TryDecryptMessageAsync(bobProv, bobConvo, aliceToBob);
    Console.WriteLine($"alice → bob: {gotByBob}");

    var bobToAlice = await MarmotChat.EncryptMessageAsync(bobProv, bobConvo, "hi alice");
    string? gotByAlice = await MarmotChat.TryDecryptMessageAsync(aliceProv, started.Conversation, bobToAlice);
    Console.WriteLine($"bob   → alice: {gotByAlice}");

    bool ok = gotByBob == "hello bob" && gotByAlice == "hi alice";
    Console.WriteLine(ok ? "✓ 1:1 marmot round-trip OK" : "✗ 1:1 marmot round-trip FAILED");
    return ok ? 0 : 1;
}
