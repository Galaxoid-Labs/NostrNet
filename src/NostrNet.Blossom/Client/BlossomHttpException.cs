// SPDX-License-Identifier: MIT
//
// Common error type for Blossom-server HTTP failures. Surfaces the
// HTTP status + the server's optional X-Reason header so callers can
// route on status codes without poking at HttpResponseMessage.

namespace NostrNet.Blossom.Client;

/// <summary>Thrown for any non-success HTTP status from a Blossom endpoint.</summary>
public class BlossomHttpException : Exception
{
    /// <summary>The HTTP status code returned by the server.</summary>
    public int StatusCode { get; }

    /// <summary>The <c>X-Reason</c> header value or the response body text, whichever was available.</summary>
    public string? ServerReason { get; }

    /// <summary>Constructs a Blossom HTTP exception.</summary>
    public BlossomHttpException(int statusCode, string? serverReason)
        : base($"Blossom server returned HTTP {statusCode}{(serverReason is null ? "" : $": {serverReason}")}.")
    {
        StatusCode = statusCode;
        ServerReason = serverReason;
    }
}
