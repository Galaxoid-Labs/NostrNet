// SPDX-License-Identifier: MIT
//
// MLS key schedule for a single epoch (RFC 9420 §9).
//
// Derivation tree used in this minimal provider:
//
//   joiner_secret  = ExpandWithLabel(
//                        KDF.Extract(init_secret_[n-1], commit_secret),
//                        "joiner", GroupContext_[n], Nh)
//   welcome_secret = ExpandWithLabel(joiner_secret, "welcome", "", Nh)
//   member_secret  = KDF.Extract(joiner_secret, psk_secret)
//   epoch_secret   = ExpandWithLabel(member_secret, "epoch", GroupContext_[n], Nh)
//
//   exporter_secret    = DeriveSecret(epoch_secret, "exporter")
//   confirmation_key   = DeriveSecret(epoch_secret, "confirm")
//   init_secret_[n]    = DeriveSecret(epoch_secret, "init")
//
//   welcome_key   = ExpandWithLabel(welcome_secret, "key", "", Nk)
//   welcome_nonce = ExpandWithLabel(welcome_secret, "nonce", "", Nn)
//
//   MLS-Exporter(label, context, L) =
//       ExpandWithLabel(
//           DeriveSecret(exporter_secret, label),
//           "exported", SHA256(context), L)
//
// For an Add-only commit with no UpdatePath, commit_secret = zeros[Nh].
// For no PSK, psk_secret = zeros[Nh].

using System.Security.Cryptography;
using NostrNet.Marmot.Mls.Reference.Crypto;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Marmot.Mls.Reference;

/// <summary>
/// The derived secrets for one MLS epoch — everything that can be
/// derived from <c>epoch_secret</c> plus the welcome-leg secrets.
/// </summary>
public sealed record EpochSecrets
{
    /// <summary>The joiner_secret. Distributed via Welcome to new members.</summary>
    public required byte[] JoinerSecret { get; init; }

    /// <summary>The welcome_secret. Used to encrypt the GroupInfo inside the Welcome.</summary>
    public required byte[] WelcomeSecret { get; init; }

    /// <summary>The full epoch_secret. Source of all per-epoch derivations.</summary>
    public required byte[] EpochSecret { get; init; }

    /// <summary>Used to seed the next epoch's key schedule.</summary>
    public required byte[] InitSecretNext { get; init; }

    /// <summary>The exporter_secret. Source of MLS-Exporter outputs.</summary>
    public required byte[] ExporterSecret { get; init; }

    /// <summary>HMAC key used for confirmation_tag (HMAC over confirmed_transcript_hash).</summary>
    public required byte[] ConfirmationKey { get; init; }

    /// <summary>AEAD key for encrypting the GroupInfo inside a Welcome.</summary>
    public required byte[] WelcomeKey { get; init; }

    /// <summary>AEAD nonce for encrypting the GroupInfo inside a Welcome.</summary>
    public required byte[] WelcomeNonce { get; init; }
}

/// <summary>MLS key-schedule derivation primitives (RFC 9420 §8.6, §9).</summary>
public static class KeySchedule
{
    /// <summary>The "marmot" / "group-event" labeled exporter Marmot uses for kind-445.</summary>
    public const string MarmotExporterLabel = "marmot";

    /// <summary>The exporter context Marmot uses (per MIP-03 §"Derive exporter secret").</summary>
    public const string MarmotExporterContext = "group-event";

    /// <summary>
    /// Derives <see cref="EpochSecrets"/> for a new epoch from the previous
    /// epoch's <paramref name="initSecretPrev"/>, the
    /// <paramref name="commitSecret"/> contributed by the committer, and
    /// the new epoch's <paramref name="groupContext"/>.
    /// </summary>
    public static EpochSecrets Derive(
        ReadOnlySpan<byte> initSecretPrev,
        ReadOnlySpan<byte> commitSecret,
        ReadOnlySpan<byte> groupContext)
    {
        if (initSecretPrev.Length != CiphersuiteInfo.Nh)
        {
            throw new ArgumentException($"initSecretPrev must be {CiphersuiteInfo.Nh} bytes.", nameof(initSecretPrev));
        }

        if (commitSecret.Length != CiphersuiteInfo.Nh)
        {
            throw new ArgumentException($"commitSecret must be {CiphersuiteInfo.Nh} bytes.", nameof(commitSecret));
        }

        // joiner_secret = ExpandWithLabel(Extract(init_secret_prev, commit_secret), "joiner", GroupContext, Nh)
        byte[] extracted = Hkdf.Extract(salt: initSecretPrev, ikm: commitSecret);
        byte[] joinerSecret;
        try
        {
            joinerSecret = Hkdf.MlsLabeledExpand(
                secret: extracted,
                label: SysEncoding.ASCII.GetBytes("joiner"),
                context: groupContext,
                length: CiphersuiteInfo.Nh);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(extracted);
        }

        return DeriveFromJoinerSecret(joinerSecret, groupContext);
    }

    /// <summary>
    /// Joiner-side derivation. Given a <paramref name="joinerSecret"/>
    /// received in a Welcome and the new epoch's
    /// <paramref name="groupContext"/>, derive the full epoch secrets.
    /// </summary>
    public static EpochSecrets DeriveFromJoinerSecret(
        ReadOnlySpan<byte> joinerSecret,
        ReadOnlySpan<byte> groupContext)
    {
        if (joinerSecret.Length != CiphersuiteInfo.Nh)
        {
            throw new ArgumentException($"joinerSecret must be {CiphersuiteInfo.Nh} bytes.", nameof(joinerSecret));
        }

        // welcome_secret = ExpandWithLabel(joiner_secret, "welcome", "", Nh)
        byte[] welcomeSecret = Hkdf.MlsLabeledExpand(
            secret: joinerSecret,
            label: SysEncoding.ASCII.GetBytes("welcome"),
            context: ReadOnlySpan<byte>.Empty,
            length: CiphersuiteInfo.Nh);

        // welcome_key, welcome_nonce
        byte[] welcomeKey = Hkdf.MlsLabeledExpand(
            secret: welcomeSecret,
            label: SysEncoding.ASCII.GetBytes("key"),
            context: ReadOnlySpan<byte>.Empty,
            length: CiphersuiteInfo.Nk);
        byte[] welcomeNonce = Hkdf.MlsLabeledExpand(
            secret: welcomeSecret,
            label: SysEncoding.ASCII.GetBytes("nonce"),
            context: ReadOnlySpan<byte>.Empty,
            length: CiphersuiteInfo.Nn);

        // member_secret = Extract(joiner_secret, psk_secret); psk_secret = zeros[Nh] for no PSK.
        byte[] zeros = new byte[CiphersuiteInfo.Nh];
        byte[] memberSecret = Hkdf.Extract(salt: joinerSecret, ikm: zeros);

        byte[] epochSecret;
        try
        {
            // epoch_secret = ExpandWithLabel(member_secret, "epoch", GroupContext, Nh)
            epochSecret = Hkdf.MlsLabeledExpand(
                secret: memberSecret,
                label: SysEncoding.ASCII.GetBytes("epoch"),
                context: groupContext,
                length: CiphersuiteInfo.Nh);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(memberSecret);
        }

        byte[] exporterSecret = Hkdf.DeriveSecret(epochSecret, SysEncoding.ASCII.GetBytes("exporter"));
        byte[] confirmationKey = Hkdf.DeriveSecret(epochSecret, SysEncoding.ASCII.GetBytes("confirm"));
        byte[] initSecretNext = Hkdf.DeriveSecret(epochSecret, SysEncoding.ASCII.GetBytes("init"));

        return new EpochSecrets
        {
            JoinerSecret = joinerSecret.ToArray(),
            WelcomeSecret = welcomeSecret,
            EpochSecret = epochSecret,
            InitSecretNext = initSecretNext,
            ExporterSecret = exporterSecret,
            ConfirmationKey = confirmationKey,
            WelcomeKey = welcomeKey,
            WelcomeNonce = welcomeNonce,
        };
    }

    /// <summary>
    /// MLS-Exporter (RFC 9420 §8.6). Derives a labeled secret from the
    /// current epoch's <paramref name="exporterSecret"/>.
    /// </summary>
    public static byte[] Export(
        ReadOnlySpan<byte> exporterSecret,
        string label,
        ReadOnlySpan<byte> context,
        int length)
    {
        ArgumentNullException.ThrowIfNull(label);

        byte[] secret = Hkdf.DeriveSecret(exporterSecret, SysEncoding.ASCII.GetBytes(label));
        try
        {
            byte[] contextHash = SHA256.HashData(context);
            return Hkdf.MlsLabeledExpand(
                secret: secret,
                label: SysEncoding.ASCII.GetBytes("exported"),
                context: contextHash,
                length: length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    /// <summary>
    /// Convenience: derive the Marmot exporter secret (Label="marmot",
    /// Context="group-event", Length=32) used by kind-445 GroupEvent
    /// content encryption per MIP-03.
    /// </summary>
    public static byte[] DeriveMarmotExporterSecret(ReadOnlySpan<byte> exporterSecret)
    {
        return Export(
            exporterSecret,
            MarmotExporterLabel,
            SysEncoding.ASCII.GetBytes(MarmotExporterContext),
            length: 32);
    }
}
