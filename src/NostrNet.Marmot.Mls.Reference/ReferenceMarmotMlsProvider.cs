// SPDX-License-Identifier: MIT
//
// Concrete IMarmotMlsProvider implementation backed by the in-tree
// reference MLS engine.
//
// Supported operations (all async, in-memory):
//   - BuildKeyPackageAsync            — generates Ed25519 + X25519 keys, signs a KeyPackage,
//                                       stashes the private material keyed by KeyPackageRef.
//   - ParseKeyPackageAsync            — decodes and verifies a KeyPackage bundle.
//   - CreateGroupAsync                — bootstraps a 1-member group with the founder.
//   - AddMembersAsync                 — adds exactly ONE member, producing a Welcome.
//   - JoinGroupFromWelcomeAsync       — joins as the recipient of a Welcome.
//   - CurrentExporterSecretAsync      — returns the live exporter secret.
//
// Unsupported operations throw NotSupportedException:
//   - BuildSelfRemoveProposalAsync
//   - EncryptApplicationMessageAsync
//   - ProcessIncomingMlsMessageAsync

using System.Diagnostics.CodeAnalysis;
using NostrNet.Keys;
using NostrNet.Marmot.GroupData;
using NostrNet.Marmot.Mls.Reference.Crypto;
using NostrNet.Marmot.Mls.Reference.Wire;
using SysEncoding = System.Text.Encoding;

namespace NostrNet.Marmot.Mls.Reference;

/// <summary>
/// In-tree, single-ciphersuite, group-of-2 MLS provider for Marmot.
/// EXPERIMENTAL — see <see cref="ExperimentalDiagnostics"/>.
/// </summary>
public sealed class ReferenceMarmotMlsProvider : IMarmotMlsProvider
{
    private readonly Dictionary<string, ReferenceMlsGroup> _groups = new(StringComparer.Ordinal);
    private readonly Dictionary<string, KeyPackageState> _keyPackages = new(StringComparer.Ordinal);
    private readonly Dictionary<string, MarmotGroupDataExtension> _groupData = new(StringComparer.Ordinal);

    /// <summary>
    /// Generates an MLS KeyPackage bundle for the given Nostr identity.
    /// Stores the corresponding private keys so the provider can later
    /// open a Welcome encrypted to this KeyPackage.
    /// </summary>
    public Task<KeyPackageBundle> BuildKeyPackageAsync(
        PublicKey identityPubkey,
        ushort ciphersuite,
        IReadOnlyList<ushort> extensions,
        IReadOnlyList<ushort> proposals,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(identityPubkey);
        CiphersuiteInfo.EnsureSupported((Ciphersuite)ciphersuite);

        Ed25519.GenerateKeyPair(out byte[] sigSk, out byte[] sigPk);
        X25519.GenerateKeyPair(out byte[] initSk, out byte[] initPk);
        X25519.GenerateKeyPair(out byte[] encSk, out byte[] encPk);

        var leaf = LeafNode.Sign(
            encryptionKey: encPk,
            signatureKey: sigPk,
            signaturePrivateKey: sigSk,
            credential: new BasicCredential(identityPubkey.AsSpan().ToArray()),
            capabilities: ReferenceMlsGroup.DefaultCapabilities(),
            lifetime: new Lifetime(0UL, ulong.MaxValue),
            extensions: Array.Empty<Wire.Extension>());

        var kp = KeyPackage.Sign(
            version: ProtocolVersion.Mls10,
            suite: (Ciphersuite)ciphersuite,
            initKey: initPk,
            leaf: leaf,
            signaturePrivateKey: sigSk);

        byte[] kpRef = kp.ComputeReference();
        string kpRefHex = Convert.ToHexStringLower(kpRef);
        _keyPackages[kpRefHex] = new KeyPackageState(kp, identityPubkey, sigSk, initSk, encSk);

        return Task.FromResult(new KeyPackageBundle(
            BundleBytes: kp.Encode(),
            Ciphersuite: ciphersuite,
            ProtocolVersion: "1.0",
            KeyPackageRef: kpRefHex));
    }

    /// <summary>Parses and verifies a KeyPackage bundle.</summary>
    public Task<KeyPackageInfo> ParseKeyPackageAsync(
        ReadOnlyMemory<byte> keyPackageBundleBytes,
        CancellationToken ct = default)
    {
        var kp = KeyPackage.Decode(keyPackageBundleBytes.Span);
        if (!kp.Verify())
        {
            throw new System.Security.Cryptography.CryptographicException("KeyPackage signature is invalid.");
        }

        // BasicCredential identity is the recipient's 32-byte x-only Nostr pubkey.
        byte[] identity = kp.Leaf.Credential.Identity;
        if (identity.Length != 32)
        {
            throw new InvalidDataException(
                $"BasicCredential identity must be 32 bytes (a Nostr pubkey); got {identity.Length}.");
        }

        var pubkey = new PublicKey(identity);
        return Task.FromResult(new KeyPackageInfo(
            IdentityPubkey: pubkey,
            Ciphersuite: (ushort)kp.Ciphersuite,
            ProtocolVersion: "1.0",
            Extensions: kp.Leaf.Capabilities.ExtensionTypes,
            Proposals: kp.Leaf.Capabilities.ProposalTypes,
            KeyPackageRef: Convert.ToHexStringLower(kp.ComputeReference())));
    }

    /// <summary>
    /// Bootstraps a new MLS group with the founder as the only member.
    /// Uses <paramref name="creatorPubkey"/> as the BasicCredential identity
    /// and <paramref name="groupData"/> as the Marmot group metadata.
    /// </summary>
    public Task<CreateGroupResult> CreateGroupAsync(
        PublicKey creatorPubkey,
        MarmotGroupDataExtension groupData,
        ushort ciphersuite,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(creatorPubkey);
        ArgumentNullException.ThrowIfNull(groupData);
        CiphersuiteInfo.EnsureSupported((Ciphersuite)ciphersuite);

        Ed25519.GenerateKeyPair(out byte[] sigSk, out byte[] sigPk);
        X25519.GenerateKeyPair(out byte[] initSk, out byte[] initPk);
        X25519.GenerateKeyPair(out byte[] encSk, out byte[] encPk);

        var group = ReferenceMlsGroup.CreateAsFounder(
            groupId: (byte[])groupData.NostrGroupId.Clone(),
            founderCredential: new BasicCredential(creatorPubkey.AsSpan().ToArray()),
            founderSignaturePublicKey: sigPk,
            founderSignaturePrivateKey: sigSk,
            founderInitPublicKey: initPk,
            founderInitPrivateKey: initSk,
            founderEncryptionPublicKey: encPk);

        string key = Convert.ToHexStringLower(groupData.NostrGroupId);
        _groups[key] = group;
        _groupData[key] = groupData;

        return Task.FromResult(new CreateGroupResult(
            NostrGroupId: (byte[])groupData.NostrGroupId.Clone(),
            InitialExporterSecret: group.MarmotExporterSecret()));
    }

    /// <summary>
    /// Adds a single member to an existing 1-member group and emits a
    /// Welcome message. The "Commit" returned is an empty byte array —
    /// the reference provider does not publish standalone Commit MLSMessages
    /// (the recipient gets all the state it needs via the Welcome).
    /// </summary>
    public Task<AddMembersResult> AddMembersAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        IReadOnlyList<ReadOnlyMemory<byte>> keyPackageBundles,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(keyPackageBundles);
        if (keyPackageBundles.Count != 1)
        {
            throw new NotSupportedException(
                $"Reference provider only supports adding exactly one member at a time; got {keyPackageBundles.Count}.");
        }

        if (!TryGetGroup(nostrGroupId, out var group))
        {
            throw new InvalidOperationException("No group with the given nostrGroupId is loaded in this provider.");
        }

        var kp = KeyPackage.Decode(keyPackageBundles[0].Span);
        if (!kp.Verify())
        {
            throw new System.Security.Cryptography.CryptographicException("Added member's KeyPackage signature is invalid.");
        }

        byte[] recipientIdentity = kp.Leaf.Credential.Identity;
        if (recipientIdentity.Length != 32)
        {
            throw new InvalidDataException("Member KeyPackage credential identity must be a 32-byte Nostr pubkey.");
        }

        byte[] welcomeBytes = group.AddMember(kp);

        return Task.FromResult(new AddMembersResult(
            CommitMlsMessageBytes: Array.Empty<byte>(),
            Welcomes: new[]
            {
                new WelcomeToSend(
                    RecipientPubkey: new PublicKey(recipientIdentity),
                    WelcomeMlsMessageBytes: welcomeBytes),
            },
            NewExporterSecret: group.MarmotExporterSecret()));
    }

    /// <summary>
    /// Joins a group as the recipient of a Welcome.
    /// </summary>
    public Task<JoinedGroupResult> JoinGroupFromWelcomeAsync(
        ReadOnlyMemory<byte> mlsWelcomeBytes,
        CancellationToken ct = default)
    {
        var welcome = Welcome.Decode(mlsWelcomeBytes.Span);

        // Look up the local KeyPackage that matches one of the
        // EncryptedGroupSecrets entries.
        KeyPackageState? state = null;
        foreach (var s in welcome.Secrets)
        {
            string hex = Convert.ToHexStringLower(s.NewMember);
            if (_keyPackages.TryGetValue(hex, out var found))
            {
                state = found;
                break;
            }
        }

        if (state is null)
        {
            throw new System.Security.Cryptography.CryptographicException(
                "No local KeyPackage matches any EncryptedGroupSecrets entry in this Welcome.");
        }

        var group = ReferenceMlsGroup.JoinFromWelcome(
            welcomeBytes: mlsWelcomeBytes.ToArray(),
            myKeyPackage: state.KeyPackage,
            myInitPrivateKey: state.InitSk,
            mySignaturePrivateKey: state.SignatureSk);

        string key = Convert.ToHexStringLower(group.Context.GroupId);
        _groups[key] = group;

        // The reference provider doesn't transmit the MarmotGroupDataExtension
        // inside the MLS layer (it lives in the kind-445 GroupEvent's `h` tag
        // and the group's relays come from the Welcome rumor's `relays` tag).
        // We synthesize a minimal one for the caller.
        var groupData = new MarmotGroupDataExtension
        {
            NostrGroupId = group.Context.GroupId,
            AdminPubkeys = new[] { new PublicKey(group.FounderLeaf.Credential.Identity) },
            Relays = Array.Empty<string>(),
        };
        _groupData[key] = groupData;

        return Task.FromResult(new JoinedGroupResult(
            NostrGroupId: (byte[])group.Context.GroupId.Clone(),
            GroupData: groupData,
            CurrentExporterSecret: group.MarmotExporterSecret()));
    }

    /// <inheritdoc/>
    public Task<byte[]> BuildSelfRemoveProposalAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        CancellationToken ct = default)
        => throw NotSupported(nameof(BuildSelfRemoveProposalAsync));

    /// <inheritdoc/>
    public Task<byte[]> EncryptApplicationMessageAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        ReadOnlyMemory<byte> plaintext,
        CancellationToken ct = default)
        => throw NotSupported(nameof(EncryptApplicationMessageAsync));

    /// <inheritdoc/>
    public Task<ProcessedMlsMessage> ProcessIncomingMlsMessageAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        ReadOnlyMemory<byte> mlsMessageBytes,
        CancellationToken ct = default)
        => throw NotSupported(nameof(ProcessIncomingMlsMessageAsync));

    /// <inheritdoc/>
    public Task<byte[]> CurrentExporterSecretAsync(
        ReadOnlyMemory<byte> nostrGroupId,
        CancellationToken ct = default)
    {
        if (!TryGetGroup(nostrGroupId, out var group))
        {
            throw new InvalidOperationException("No group with the given nostrGroupId is loaded in this provider.");
        }

        return Task.FromResult(group.MarmotExporterSecret());
    }

    private bool TryGetGroup(ReadOnlyMemory<byte> nostrGroupId, [NotNullWhen(true)] out ReferenceMlsGroup? group)
    {
        string key = Convert.ToHexStringLower(nostrGroupId.Span);
        return _groups.TryGetValue(key, out group);
    }

    private static NotSupportedException NotSupported(string method)
    {
        return new NotSupportedException(
            $"{method} is not supported by NostrNet.Marmot.Mls.Reference (experimental). "
            + "Marmot kind-445 GroupEvent encryption is keyed off the exporter secret, "
            + "which is available via CurrentExporterSecretAsync.");
    }

    private sealed record KeyPackageState(
        KeyPackage KeyPackage,
        PublicKey Identity,
        byte[] SignatureSk,
        byte[] InitSk,
        byte[] EncSk);
}
