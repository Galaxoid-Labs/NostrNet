// SPDX-License-Identifier: MIT
//
// One-line NIP-05 verification helpers for callers who don't need
// the rich Nip05VerificationResult (relays list, failure reason).
// All three overloads of Nip05.VerifyAsync are fail-closed already,
// so the bool wrappers can't surface false-positives.

using NostrNet.Events;
using NostrNet.Profiles;

namespace NostrNet.Relay;

/// <summary>
/// Convenience extensions for the common "did this profile's NIP-05
/// claim verify?" question, returning a plain <c>bool</c>. For richer
/// diagnostics (failure reason, recommended relays) call
/// <see cref="Nip05.VerifyAsync(Profile, HttpClient?, CancellationToken)"/> etc. directly.
/// </summary>
public static class Nip05Extensions
{
    /// <summary>
    /// Returns <c>true</c> when this profile's <see cref="Profile.Nip05"/>
    /// identifier resolves to its <see cref="Profile.Owner"/>. Fail-closed:
    /// any failure (no identifier, no owner, network error, mismatch,
    /// malformed document) returns <c>false</c>.
    /// </summary>
    public static async Task<bool> IsNip05VerifiedAsync(
        this Profile profile,
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var result = await Nip05.VerifyAsync(profile, httpClient, cancellationToken).ConfigureAwait(false);
        return result.IsVerified;
    }

    /// <summary>
    /// Returns <c>true</c> when this kind-0 metadata event's claimed
    /// <c>nip05</c> resolves to the event's pubkey. Fail-closed.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="kind0Event"/> is not kind 0.</exception>
    public static async Task<bool> IsNip05VerifiedAsync(
        this NostrEvent kind0Event,
        HttpClient? httpClient = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(kind0Event);
        var result = await Nip05.VerifyAsync(kind0Event, httpClient, cancellationToken).ConfigureAwait(false);
        return result.IsVerified;
    }
}
