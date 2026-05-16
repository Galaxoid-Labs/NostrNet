// SPDX-License-Identifier: MIT

namespace NostrNet.Marmot.Mls.Native;

/// <summary>
/// Thrown by <see cref="OpenMlsProvider.OpenAtPath"/> when the supplied
/// key does not decrypt the SQLCipher-encrypted MLS state file at the
/// given path. Apps should treat this as a wrong-passphrase case (prompt
/// the user to re-enter, drop back to a sign-in flow, etc.) rather than
/// a generic storage failure.
/// </summary>
/// <remarks>
/// The underlying signal is SQLite's <c>SQLITE_NOTADB</c> on the first
/// read after <c>PRAGMA key</c>. SQLCipher cannot distinguish "wrong key"
/// from "this file isn't a database at all", but in practice this only
/// fires when the key is wrong — passing an arbitrary non-DB file
/// produces the same exception, which is fine: both are "we can't open
/// this state with the supplied key, prompt the user".
/// </remarks>
public sealed class InvalidMlsKeyException : Exception
{
    /// <summary>Initializes a new instance with the given message.</summary>
    public InvalidMlsKeyException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance with a message and an inner exception.</summary>
    public InvalidMlsKeyException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
