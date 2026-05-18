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
//   marmot-chat <nsec> [opts]            — interactive Marmot REPL over real relays

using NostrNet.Client;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Marmot;
using NostrNet.Marmot.Mls.Native;
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
        "marmot-chat" => await MarmotChatAsync(args),
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

    Console.WriteLine("  to recipient:");
    foreach ((Uri uri, var r) in results.ToRecipient)
    {
        Console.WriteLine($"    {uri}: {(r.Accepted ? "OK" : "REJECTED")} {r.Message}");
    }

    Console.WriteLine("  to self (cross-device history):");
    foreach ((Uri uri, var r) in results.ToSelf)
    {
        Console.WriteLine($"    {uri}: {(r.Accepted ? "OK" : "REJECTED")} {r.Message}");
    }

    return results.ToRecipient.Values.Any(r => r.Accepted) ? 0 : 2;
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
    Console.Error.WriteLine("  marmot-chat <nsec> [opts]            interactive Marmot REPL on real relays");
    Console.Error.WriteLine("    options:");
    Console.Error.WriteLine("      --state-path <file>              SQLite path to persist MLS state (default: in-memory)");
    Console.Error.WriteLine("      --peer <npub>                    fetch their KeyPackage and start a 1:1 immediately");
    Console.Error.WriteLine("      --relay <wss-uri>                add a relay (repeatable; default = built-in 3 relays)");
    Console.Error.WriteLine("      --auto-accept                    auto-accept incoming invites (default: prompt)");
    Console.Error.WriteLine("    REPL commands:");
    Console.Error.WriteLine("      <text>                send <text> to the active conversation");
    Console.Error.WriteLine("      /list                 list joined conversations");
    Console.Error.WriteLine("      /switch <N>           make conversation #N active for plain-text sends");
    Console.Error.WriteLine("      /accept <N>           accept the Nth pending invite");
    Console.Error.WriteLine("      /start <npub>         fetch peer's KeyPackage and start a 1:1");
    Console.Error.WriteLine("      /add <npub>           add a peer to the active conversation");
    Console.Error.WriteLine("      /rotate               rotate your MLS leaf keys in the active conversation");
    Console.Error.WriteLine("      /quit                 exit");
}

// Drives the full Marmot + OpenMLS 1:1 chat flow end-to-end without
// touching the network. Useful both as a demo of the MarmotChat helper
// and as the AOT-publish smoke test for the OpenMLS-backed MLS provider.
async Task<int> MarmotMlsSmokeAsync()
{
    using var aliceKey = PrivateKey.Generate();
    using var bobKey = PrivateKey.Generate();

    using var aliceProv = new OpenMlsProvider();
    using var bobProv = new OpenMlsProvider();
    var relays = new[] { "wss://relay.example" };

    // Bob publishes his KeyPackage event (kind-30443). In a real app this
    // would be sent to his inbox relays.
    var bobKpEvent = await MarmotChat.BuildKeyPackageEventAsync(
        bobProv, bobKey, slot: null, relays);

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
    var aliceToBob = await MarmotChat.EncryptMessageAsync(aliceProv, started.Conversation, aliceKey, "hello bob");
    string? gotByBob = await MarmotChat.TryDecryptMessageAsync(bobProv, bobConvo, aliceToBob);
    Console.WriteLine($"alice → bob: {gotByBob}");

    var bobToAlice = await MarmotChat.EncryptMessageAsync(bobProv, bobConvo, bobKey, "hi alice");
    string? gotByAlice = await MarmotChat.TryDecryptMessageAsync(aliceProv, started.Conversation, bobToAlice);
    Console.WriteLine($"bob   → alice: {gotByAlice}");

    bool ok = gotByBob == "hello bob" && gotByAlice == "hi alice";
    Console.WriteLine(ok ? "✓ 1:1 marmot round-trip OK" : "✗ 1:1 marmot round-trip FAILED");
    return ok ? 0 : 1;
}

// Interactive REPL over the high-level NostrMarmotClient. Connects to
// the configured relays, publishes a fresh KeyPackage, and pumps
// MarmotInboundEvent → stdout while reading slash-commands and
// plaintext lines from stdin.
async Task<int> MarmotChatAsync(string[] argv)
{
    if (argv.Length < 2)
    {
        Console.Error.WriteLine("usage: marmot-chat <nsec> [--state-path <file>] [--peer <npub>] [--relay <wss>...] [--auto-accept]");
        return 64;
    }

    using var key = PrivateKey.FromNsec(argv[1]);

    string? statePath = null;
    PublicKey? initialPeer = null;
    bool autoAccept = false;
    var relays = new List<string>();
    for (int i = 2; i < argv.Length; i++)
    {
        switch (argv[i])
        {
            case "--state-path" when i + 1 < argv.Length:
                statePath = argv[++i];
                break;
            case "--peer" when i + 1 < argv.Length:
                initialPeer = PublicKey.FromNpub(argv[++i]);
                break;
            case "--relay" when i + 1 < argv.Length:
                relays.Add(argv[++i]);
                break;
            case "--auto-accept":
                autoAccept = true;
                break;
            default:
                Console.Error.WriteLine($"unknown option: {argv[i]}");
                return 64;
        }
    }

    if (relays.Count == 0)
    {
        relays.AddRange(DefaultRelays);
    }

    OpenMlsProvider provider;
    if (statePath is null)
    {
        provider = new OpenMlsProvider();
    }
    else
    {
        // Derive a 32-byte raw key from the user's nsec via HKDF-SHA256.
        // Real apps would use a per-app salt + version-tagged info string
        // (so future re-keying remains possible); the sample uses simple
        // constants for clarity. The key feeds SQLCipher directly — the
        // library doesn't run a KDF on it.
        Span<byte> keyBytes = stackalloc byte[32];
        Span<byte> mlsKey = stackalloc byte[32];
        try
        {
            key.CopyTo(keyBytes);
            System.Security.Cryptography.HKDF.DeriveKey(
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                ikm: keyBytes,
                output: mlsKey,
                salt: "NostrNet.Sample.Console:marmot-mls/v1"u8,
                info: "mls-state-encryption"u8);
            provider = OpenMlsProvider.OpenAtPath(statePath, mlsKey);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(keyBytes);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(mlsKey);
        }
    }

    Console.WriteLine($"identity: {key.PublicKey.ToNpub()}");
    Console.WriteLine($"relays:   {string.Join(", ", relays)}");
    Console.WriteLine($"state:    {(statePath ?? "in-memory")}");

    NostrMarmotClient client;
    try
    {
        client = await NostrMarmotClient.Builder(key, provider)
            .UseRelays(relays.ToArray())
            .ConnectAsync()
            .ConfigureAwait(false);
    }
    catch
    {
        provider.Dispose();
        throw;
    }

    await using (client)
    {
        var kpEvent = await client.PublishKeyPackageAsync().ConfigureAwait(false);
        Console.WriteLine($"published KeyPackage {kpEvent.Id.ToHex()[..16]}…");

        // Mutable state shared between the reader and inbound pump.
        var conversations = new List<MarmotConversation>();
        var pendingInvites = new List<MarmotInviteReceived>();
        int active = -1;
        var stateLock = new object();

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { cts.Cancel(); e.Cancel = true; };

        // Load conversations from previous sessions (if --state-path was
        // supplied with an existing DB). Each gets its own kind-445
        // subscription via TrackConversation inside the client.
        var existing = await client.LoadExistingConversationsAsync(cts.Token).ConfigureAwait(false);
        if (existing.Count > 0)
        {
            lock (stateLock)
            {
                conversations.AddRange(existing);
                active = 0;
            }
            Console.WriteLine($"loaded {existing.Count} existing conversation{(existing.Count == 1 ? "" : "s")} from state:");
            foreach (var (c, i) in existing.Select((c, i) => (c, i)))
            {
                string gidHex = Convert.ToHexStringLower(c.NostrGroupId);
                string peerLabel = c.Peer is { } pk ? pk.ToNpub()[..16] + "…" : "(group)";
                Console.WriteLine($"  #{i}  {peerLabel}  group {gidHex}");
            }
        }

        if (initialPeer is { } peer)
        {
            // If a conversation with this peer already exists from a
            // prior session, just resume it instead of starting a new
            // one. Real apps would do the same to avoid creating
            // duplicate groups every time the user opens a chat.
            int existingIdx;
            lock (stateLock)
            {
                existingIdx = IndexOfPeer(conversations, peer);
            }

            if (existingIdx >= 0)
            {
                lock (stateLock) { active = existingIdx; }
                Console.WriteLine($"resumed conversation #{existingIdx} with {peer.ToNpub()[..16]}…");
            }
            else
            {
                Console.WriteLine($"fetching KeyPackage for {peer.ToNpub()}...");
                var kp = await client.TryGetKeyPackageAsync(peer, TimeSpan.FromSeconds(10), cts.Token).ConfigureAwait(false);
                if (kp is null)
                {
                    Console.Error.WriteLine("  no KeyPackage found within 10s — the peer may not have published one yet.");
                }
                else
                {
                    var convo = await client.StartConversationAsync(kp, conversationName: null, ct: cts.Token).ConfigureAwait(false);
                    lock (stateLock)
                    {
                        conversations.Add(convo);
                        active = conversations.Count - 1;
                    }
                    Console.WriteLine($"started conversation #{active} with {peer.ToNpub()[..16]}…");
                }
            }
        }

        // Pump inbound events to stdout.
        var pump = Task.Run(async () =>
        {
            try
            {
                await foreach (var ev in client.SubscribeAsync(cts.Token))
                {
                    switch (ev)
                    {
                        case MarmotInviteReceived invite:
                            if (autoAccept)
                            {
                                try
                                {
                                    var convo = await client.AcceptInviteAsync(invite, cts.Token).ConfigureAwait(false);
                                    if (convo is null)
                                    {
                                        // Stale or duplicate Welcome — silently skip; nothing for the user to do.
                                        break;
                                    }

                                    int n;
                                    bool isNew;
                                    lock (stateLock)
                                    {
                                        n = IndexOfGroup(conversations, convo.NostrGroupId, stateLock);
                                        if (n < 0)
                                        {
                                            conversations.Add(convo);
                                            n = conversations.Count - 1;
                                            if (active < 0) active = n;
                                            isNew = true;
                                        }
                                        else
                                        {
                                            isNew = false;
                                        }
                                    }
                                    if (isNew)
                                    {
                                        Console.WriteLine($"\n[invite] auto-accepted from {invite.Sender.ToNpub()[..16]}… → conversation #{n}");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Console.Error.WriteLine($"\n[invite] auto-accept failed: {ex.Message}");
                                }
                            }
                            else
                            {
                                int idx;
                                lock (stateLock)
                                {
                                    pendingInvites.Add(invite);
                                    idx = pendingInvites.Count - 1;
                                }
                                Console.WriteLine($"\n[invite] #{idx} from {invite.Sender.ToNpub()[..16]}… — type /accept {idx} to join");
                            }
                            break;

                        case MarmotMessageReceived msg:
                            string from = msg.Sender?.ToNpub()[..16] ?? "<unknown>";
                            int cidx = IndexOf(conversations, msg.Conversation, stateLock);
                            Console.WriteLine($"\n[#{cidx} {from}…] {msg.Plaintext}");
                            break;

                        case MarmotGroupStateChanged gsc:
                            string by = gsc.Sender?.ToNpub()[..16] ?? "<unknown>";
                            int gidx = IndexOf(conversations, gsc.Conversation, stateLock);
                            Console.WriteLine($"\n[#{gidx}] group state changed by {by}…");
                            break;
                    }

                    Console.Write("> ");
                }
            }
            catch (OperationCanceledException) { /* shutdown */ }
        });

        Console.WriteLine("REPL ready. Type /help for commands, /quit to exit.");
        Console.Write("> ");

        while (!cts.IsCancellationRequested)
        {
            string? line = await Task.Run(Console.In.ReadLineAsync).ConfigureAwait(false);
            if (line is null)
            {
                break;
            }

            line = line.Trim();
            if (line.Length == 0)
            {
                Console.Write("> ");
                continue;
            }

            if (line == "/quit")
            {
                break;
            }

            if (line == "/help")
            {
                Console.WriteLine("  <text>             send to active conversation");
                Console.WriteLine("  /list              list conversations");
                Console.WriteLine("  /switch <N>        make #N the active conversation");
                Console.WriteLine("  /accept <N>        accept invite #N");
                Console.WriteLine("  /start <npub>      start a 1:1");
                Console.WriteLine("  /add <npub>        add a peer to the active conversation");
                Console.WriteLine("  /rotate            self-update MLS keys in active conversation");
                Console.WriteLine("  /quit              exit");
                Console.Write("> ");
                continue;
            }

            if (line == "/list")
            {
                lock (stateLock)
                {
                    for (int i = 0; i < conversations.Count; i++)
                    {
                        string marker = i == active ? "*" : " ";
                        string gid = Convert.ToHexStringLower(conversations[i].NostrGroupId);
                        string peerLabel = conversations[i].Peer is { } pk
                            ? pk.ToNpub()[..16] + "…"
                            : "(group)";
                        Console.WriteLine($"  {marker} #{i}  {peerLabel}  group {gid}");
                    }

                    if (conversations.Count == 0)
                    {
                        Console.WriteLine("  (none)");
                    }
                }

                Console.Write("> ");
                continue;
            }

            if (line.StartsWith("/switch ", StringComparison.Ordinal) &&
                int.TryParse(line[8..].Trim(), out int sIdx))
            {
                lock (stateLock)
                {
                    if (sIdx < 0 || sIdx >= conversations.Count)
                    {
                        Console.WriteLine($"  no conversation #{sIdx}");
                    }
                    else
                    {
                        active = sIdx;
                        Console.WriteLine($"  active = #{active}");
                    }
                }

                Console.Write("> ");
                continue;
            }

            if (line.StartsWith("/accept ", StringComparison.Ordinal) &&
                int.TryParse(line[8..].Trim(), out int aIdx))
            {
                MarmotInviteReceived? invite = null;
                lock (stateLock)
                {
                    if (aIdx >= 0 && aIdx < pendingInvites.Count)
                    {
                        invite = pendingInvites[aIdx];
                    }
                }

                if (invite is null)
                {
                    Console.WriteLine($"  no pending invite #{aIdx}");
                }
                else
                {
                    try
                    {
                        var convo = await client.AcceptInviteAsync(invite, cts.Token).ConfigureAwait(false);
                        if (convo is null)
                        {
                            Console.WriteLine("  invite stale (the local KeyPackage it references is gone); skipped.");
                        }
                        else
                        {
                            int n;
                            lock (stateLock)
                            {
                                n = IndexOfGroup(conversations, convo.NostrGroupId, stateLock);
                                if (n < 0)
                                {
                                    conversations.Add(convo);
                                    n = conversations.Count - 1;
                                    if (active < 0) active = n;
                                }
                            }
                            Console.WriteLine($"  joined as conversation #{n}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"  accept failed: {ex.Message}");
                    }
                }

                Console.Write("> ");
                continue;
            }

            if (line.StartsWith("/start ", StringComparison.Ordinal))
            {
                try
                {
                    var peerKey = PublicKey.FromNpub(line[7..].Trim());
                    var kp = await client.TryGetKeyPackageAsync(peerKey, TimeSpan.FromSeconds(10), cts.Token).ConfigureAwait(false);
                    if (kp is null)
                    {
                        Console.WriteLine("  no KeyPackage found.");
                    }
                    else
                    {
                        var convo = await client.StartConversationAsync(kp, conversationName: null, ct: cts.Token).ConfigureAwait(false);
                        int n;
                        lock (stateLock)
                        {
                            conversations.Add(convo);
                            n = conversations.Count - 1;
                            active = n;
                        }
                        Console.WriteLine($"  started conversation #{n}");
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"  start failed: {ex.Message}");
                }

                Console.Write("> ");
                continue;
            }

            if (line.StartsWith("/add ", StringComparison.Ordinal))
            {
                MarmotConversation? convo = null;
                lock (stateLock)
                {
                    if (active >= 0 && active < conversations.Count)
                    {
                        convo = conversations[active];
                    }
                }

                if (convo is null)
                {
                    Console.WriteLine("  no active conversation.");
                }
                else
                {
                    try
                    {
                        var peerKey = PublicKey.FromNpub(line[5..].Trim());
                        var kp = await client.TryGetKeyPackageAsync(peerKey, TimeSpan.FromSeconds(10), cts.Token).ConfigureAwait(false);
                        if (kp is null)
                        {
                            Console.WriteLine("  no KeyPackage found.");
                        }
                        else
                        {
                            await client.AddPeerAsync(convo, kp, cts.Token).ConfigureAwait(false);
                            Console.WriteLine("  add committed.");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"  add failed: {ex.Message}");
                    }
                }

                Console.Write("> ");
                continue;
            }

            if (line == "/rotate")
            {
                MarmotConversation? convo = null;
                lock (stateLock)
                {
                    if (active >= 0 && active < conversations.Count)
                    {
                        convo = conversations[active];
                    }
                }

                if (convo is null)
                {
                    Console.WriteLine("  no active conversation.");
                }
                else
                {
                    try
                    {
                        await client.RotateKeysAsync(convo, cts.Token).ConfigureAwait(false);
                        Console.WriteLine("  rotated.");
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"  rotate failed: {ex.Message}");
                    }
                }

                Console.Write("> ");
                continue;
            }

            // Plain-text send to active conversation.
            MarmotConversation? sendTo = null;
            lock (stateLock)
            {
                if (active >= 0 && active < conversations.Count)
                {
                    sendTo = conversations[active];
                }
            }

            if (sendTo is null)
            {
                Console.WriteLine("  no active conversation — use /start <npub> or /accept <N> first.");
            }
            else
            {
                try
                {
                    await client.SendAsync(sendTo, line, ct: cts.Token).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"  send failed: {ex.Message}");
                }
            }

            Console.Write("> ");
        }

        cts.Cancel();
        try
        {
            await pump.ConfigureAwait(false);
        }
        catch
        {
            // pump errors during shutdown are non-fatal
        }
    }

    Console.WriteLine();
    Console.WriteLine("bye.");
    return 0;

    static int IndexOf(List<MarmotConversation> list, MarmotConversation convo, object @lock)
    {
        lock (@lock)
        {
            for (int i = 0; i < list.Count; i++)
            {
                if (list[i].NostrGroupId.AsSpan().SequenceEqual(convo.NostrGroupId.AsSpan()))
                {
                    return i;
                }
            }
        }

        return -1;
    }

    // Caller-locked variant for use inside an already-held lock.
    static int IndexOfGroup(List<MarmotConversation> list, byte[] nostrGroupId, object @lock)
    {
        for (int i = 0; i < list.Count; i++)
        {
            if (list[i].NostrGroupId.AsSpan().SequenceEqual(nostrGroupId.AsSpan()))
            {
                return i;
            }
        }

        return -1;
    }

    // Match a 1:1 conversation by the peer's pubkey. Returns -1 if no
    // existing conversation pairs with this peer.
    static int IndexOfPeer(List<MarmotConversation> list, PublicKey peer)
    {
        for (int i = 0; i < list.Count; i++)
        {
            if (list[i].Peer is { } p && p.Equals(peer))
            {
                return i;
            }
        }

        return -1;
    }
}
