// SPDX-License-Identifier: MIT
//
// NostrClient convenience extensions for Blossom NIPs. These live in
// NostrNet.Blossom (not NostrNet.Client) so the Client package doesn't
// need to know Blossom exists. Consumers add NostrNet.Blossom to pull
// in both the typed events and these helpers.

using NostrNet.Blossom.UserServers;
using NostrNet.Client;
using NostrNet.Events;
using NostrNet.Keys;
using NostrNet.Relay;

namespace NostrNet.Blossom;

/// <summary>Blossom-specific helpers on top of <see cref="NostrClient"/>.</summary>
public static class NostrClientBlossomExtensions
{
    /// <summary>
    /// Builds and publishes a NIP-B7 user server list (kind 10063)
    /// listing the user's preferred Blossom servers, in the supplied
    /// order. The list replaces any prior kind-10063 event for the
    /// signing pubkey on relays that honor NIP-33 replacement.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="serverUrls"/> is empty.</exception>
    /// <exception cref="InvalidOperationException">The client was constructed without a key.</exception>
    public static async Task<IReadOnlyDictionary<Uri, PublishResult>> PublishBlossomServerListAsync(
        this NostrClient client,
        IReadOnlyList<string> serverUrls,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(serverUrls);
        if (serverUrls.Count == 0)
        {
            throw new ArgumentException(
                "NIP-B7 server list must contain at least one server.", nameof(serverUrls));
        }

        // Build & sign via the client's private key.
        var ev = BlossomServerList.Create().AddServers(serverUrls).BuildAndSign(client.RequireSigningKey());
        return await client.PublishAsync(ev, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Fetches a user's most recent NIP-B7 server list from any
    /// configured relay. Returns <c>null</c> if no kind-10063 event
    /// is found before <paramref name="timeout"/> elapses.
    /// </summary>
    public static async Task<BlossomServerList?> TryGetBlossomServerListAsync(
        this NostrClient client,
        PublicKey owner,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(owner);

        var filter = new Filter
        {
            Kinds = new[] { BlossomKinds.UserServerList },
            Authors = new[] { owner.ToHex() },
            Limit = 1,
        };

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout ?? TimeSpan.FromSeconds(5));

        // Relay replacement (kind 10000-19999) means we should see at
        // most one event per author; if multiple relays disagree, we
        // keep the highest created_at.
        BlossomServerList? best = null;
        try
        {
            await foreach (var received in client.SubscribeAsync(new[] { filter }, cts.Token).ConfigureAwait(false))
            {
                if (received.Event.Kind != BlossomKinds.UserServerList) continue;
                if (!received.Event.PubKey.Equals(owner)) continue;

                var list = BlossomServerList.FromEvent(received.Event);
                if (best is null || list.CreatedAt > best.CreatedAt)
                {
                    best = list;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Timeout — return whatever we have (may still be null).
        }

        return best;
    }

    /// <summary>
    /// Extracts the signing key from the client, throwing the same
    /// <see cref="InvalidOperationException"/> shape as the client's
    /// own helpers if it's key-less. Public via this extension so
    /// other Blossom helpers (signed-auth events, etc.) can reuse it
    /// without each implementing the check.
    /// </summary>
    internal static PrivateKey RequireSigningKey(this NostrClient client)
    {
        var key = client.SigningKey;
        return key ?? throw new InvalidOperationException(
            "This NostrClient was constructed without a signing key — Blossom helpers that publish events need one.");
    }
}
