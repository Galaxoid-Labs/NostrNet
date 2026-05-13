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

using NostrNet.Client;
using NostrNet.Events;
using NostrNet.Keys;
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
        await foreach (var ev in client.SubscribeNotesAsync(
            authors: new[] { key.PublicKey },
            limit: 50,
            cancellationToken: cts.Token).ConfigureAwait(false))
        {
            string preview = ev.Content.Length > 80 ? ev.Content[..77] + "..." : ev.Content;
            preview = preview.ReplaceLineEndings(" ");
            Console.WriteLine($"  {ev.CreatedAt}  {preview}");
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
}
