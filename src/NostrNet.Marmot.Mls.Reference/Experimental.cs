// SPDX-License-Identifier: MIT

namespace NostrNet.Marmot.Mls.Reference;

/// <summary>
/// Diagnostic id for the <see cref="System.Diagnostics.CodeAnalysis.ExperimentalAttribute"/>
/// applied to types in this package. Consumers must explicitly suppress
/// <c>NMARMOT0001</c> (e.g. via <c>&lt;NoWarn&gt;</c>) to acknowledge they
/// understand this is a minimal-scope, non-audited, non-interop MLS
/// implementation suitable only for experimentation.
/// </summary>
public static class ExperimentalDiagnostics
{
    /// <summary>Diagnostic id for the experimental warning.</summary>
    public const string DiagnosticId = "NMARMOT0001";

    /// <summary>The single-line summary surfaced with the warning.</summary>
    public const string Description =
        "NostrNet.Marmot.Mls.Reference is an EXPERIMENTAL minimal MLS implementation. "
        + "It supports one ciphersuite and two-member groups only. "
        + "Not audited; not constant-time; does not interop with OpenMLS. "
        + "For production, prefer an OpenMLS FFI provider.";
}
