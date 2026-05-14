// SPDX-License-Identifier: MIT

namespace NostrNet.Marmot;

/// <summary>Nostr event-kind constants and ciphersuite IDs for the Marmot protocol.</summary>
public static class MarmotKinds
{
    /// <summary>NIP-style KeyPackage event (MIP-00, parameterized replaceable).</summary>
    public const int KeyPackage = 30443;

    /// <summary>Welcome rumor wrapped inside a NIP-59 gift wrap (MIP-02).</summary>
    public const int WelcomeRumor = 444;

    /// <summary>Group event carrying an encrypted MLSMessage (MIP-03).</summary>
    public const int GroupEvent = 445;

    /// <summary>Push-notification trigger rumor wrapped inside a NIP-59 gift wrap (MIP-05, draft).</summary>
    public const int PushNotificationRumor = 446;
}

/// <summary>MLS extension identifiers used by Marmot.</summary>
public static class MarmotMlsExtensions
{
    /// <summary>The Marmot Group Data extension identifier (MIP-01).</summary>
    public const ushort MarmotGroupData = 0xF2EE;

    /// <summary>The MLS <c>last_resort</c> KeyPackage extension (draft-ietf-mls-extensions §4.2.5).</summary>
    public const ushort LastResort = 0x000A;
}

/// <summary>MLS proposal-type identifiers required by Marmot.</summary>
public static class MarmotMlsProposalTypes
{
    /// <summary>The <c>self_remove</c> proposal type required by MIP-03.</summary>
    public const ushort SelfRemove = 0x000A;
}
