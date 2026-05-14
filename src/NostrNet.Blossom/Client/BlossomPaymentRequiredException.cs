// SPDX-License-Identifier: MIT
//
// BUD-07: Servers signal payment requirements via HTTP 402 plus one
// or more `X-{payment_method}` response headers. Clients complete the
// payment out-of-band, then retry the same request with their proof
// in an `X-{payment_method}` request header.
//
// This exception type surfaces the server-provided payment quotes to
// callers so they can render UI / hand off to a wallet without
// having to inspect raw HttpResponseMessage objects.

namespace NostrNet.Blossom.Client;

/// <summary>
/// Thrown when a Blossom server responds with 402 Payment Required.
/// Carries the server-supplied payment quote headers so callers can
/// surface them to a wallet (or to the user for manual settlement).
/// </summary>
public sealed class BlossomPaymentRequiredException : BlossomHttpException
{
    /// <summary>BOLT-11 lightning invoice quotes from <c>X-Lightning</c> headers (zero or more).</summary>
    public IReadOnlyList<string> LightningInvoices { get; }

    /// <summary>Cashu token quotes from <c>X-Cashu</c> headers (zero or more).</summary>
    public IReadOnlyList<string> CashuQuotes { get; }

    /// <summary>Other <c>X-{method}</c> headers we don't natively recognise — preserved for forward compat.</summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> OtherPaymentHeaders { get; }

    /// <param name="reason">The server's optional <c>X-Reason</c> diagnostic.</param>
    /// <param name="lightning">Quotes from <c>X-Lightning</c> headers.</param>
    /// <param name="cashu">Quotes from <c>X-Cashu</c> headers.</param>
    /// <param name="otherPaymentHeaders">Quotes from non-standard <c>X-{method}</c> headers.</param>
    public BlossomPaymentRequiredException(
        string? reason,
        IReadOnlyList<string> lightning,
        IReadOnlyList<string> cashu,
        IReadOnlyDictionary<string, IReadOnlyList<string>> otherPaymentHeaders)
        : base(402, reason ?? "Payment required.")
    {
        LightningInvoices = lightning;
        CashuQuotes = cashu;
        OtherPaymentHeaders = otherPaymentHeaders;
    }
}
