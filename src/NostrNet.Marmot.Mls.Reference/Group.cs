// SPDX-License-Identifier: MIT
//
// Group state machine for the reference MLS provider.
//
// Supported transitions:
//   - CreateAsFounder       : new 1-member group at epoch 0.
//   - AddMember             : 1→2 members via Add proposal + Commit with no UpdatePath.
//                             Produces a Welcome blob for the new member.
//   - JoinFromWelcome       : 0→1 members on the new member's side, lifted to epoch 1.
//
// Anything beyond (more members, removes, updates, paths) throws
// NotSupportedException. The minimum-viable contract is that after an
// AddMember + JoinFromWelcome pair, both sides agree on the exporter
// secret, which is what Marmot kind-445 GroupEvent encryption consumes.
//
// Non-standard simplifications vs strict RFC 9420:
//   - confirmed_transcript_hash = "" (32-byte zero or empty; we choose
//     empty bytes for simplicity). Both sides agree.
//   - No ratchet_tree extension; instead, the founder's leaf travels in
//     a private-use extension type 0xFE01 so the joiner can verify the
//     GroupInfo signer.
//   - psks vector is always empty.

using System.Security.Cryptography;
using NostrNet.Marmot.Mls.Reference.Crypto;
using NostrNet.Marmot.Mls.Reference.Wire;

namespace NostrNet.Marmot.Mls.Reference;

/// <summary>
/// Reference-provider MLS group state. Holds enough state to compute
/// the current epoch's exporter secret and to add one more member.
/// </summary>
internal sealed class ReferenceMlsGroup
{
    /// <summary>Custom (private-use) extension type for the founder's leaf inside GroupInfo.</summary>
    public const ushort FounderLeafExtensionType = 0xFE01;

    private static readonly byte[] ZerosNh = new byte[CiphersuiteInfo.Nh];

    private ReferenceMlsGroup(
        GroupContext context,
        EpochSecrets secrets,
        LeafNode founderLeaf,
        LeafNode? memberLeaf,
        byte[] founderSignatureSk,
        byte[]? founderInitSk,
        byte[]? memberInitSk)
    {
        Context = context;
        Secrets = secrets;
        FounderLeaf = founderLeaf;
        MemberLeaf = memberLeaf;
        FounderSignatureSk = founderSignatureSk;
        FounderInitSk = founderInitSk;
        MemberInitSk = memberInitSk;
    }

    /// <summary>Current GroupContext.</summary>
    public GroupContext Context { get; private set; }

    /// <summary>Derived secrets for the current epoch.</summary>
    public EpochSecrets Secrets { get; private set; }

    /// <summary>The founder's leaf (leaf index 0).</summary>
    public LeafNode FounderLeaf { get; }

    /// <summary>The added member's leaf (leaf index 1) — null until the group has 2 members.</summary>
    public LeafNode? MemberLeaf { get; private set; }

    /// <summary>The signature private key for the local member (founder if this side ran CreateAsFounder).</summary>
    public byte[] FounderSignatureSk { get; }

    /// <summary>The founder's HPKE init private key. <c>null</c> on the joiner's side.</summary>
    public byte[]? FounderInitSk { get; }

    /// <summary>The joiner's HPKE init private key. <c>null</c> on the founder's side.</summary>
    public byte[]? MemberInitSk { get; }

    /// <summary>
    /// MLS-Exporter("marmot", "group-event", 32). The 32-byte key Marmot
    /// kind-445 GroupEvent encryption uses for ChaCha20-Poly1305.
    /// </summary>
    public byte[] MarmotExporterSecret()
        => KeySchedule.DeriveMarmotExporterSecret(Secrets.ExporterSecret);

    /// <summary>
    /// The local member's leaf index — 0 if this side created the group,
    /// 1 if this side joined via a Welcome. Used to pick the right
    /// outbound application ratchet.
    /// </summary>
    public uint LocalLeafIndex => FounderInitSk is not null ? 0u : 1u;

    /// <summary>The peer's leaf index — the other of 0 / 1.</summary>
    public uint PeerLeafIndex => LocalLeafIndex == 0u ? 1u : 0u;

    private ApplicationRatchet? _outboundRatchet;
    private ApplicationRatchet? _inboundRatchet;
    private long _highestSeenInboundGeneration = -1;

    private ApplicationRatchet GetOrCreateOutboundRatchet()
        => _outboundRatchet ??= new ApplicationRatchet(
            ApplicationRatchet.DeriveLeafBaseSecret(Secrets.EncryptionSecret, LocalLeafIndex));

    private ApplicationRatchet GetOrCreateInboundRatchet()
        => _inboundRatchet ??= new ApplicationRatchet(
            ApplicationRatchet.DeriveLeafBaseSecret(Secrets.EncryptionSecret, PeerLeafIndex));

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> as an application message
    /// using the local member's outbound ratchet, advancing the
    /// generation. Returns the full serialized
    /// <see cref="ApplicationMessageCodec"/> bytes — pass these as the
    /// <c>mlsMessageBytes</c> to <see cref="Events.GroupEvent.Build"/>.
    /// </summary>
    public byte[] EncryptApplicationMessage(ReadOnlySpan<byte> plaintext)
    {
        if (MemberLeaf is null)
        {
            throw new InvalidOperationException(
                "Application messages require a 2-member group. Run AddMember (or JoinFromWelcome) first.");
        }

        var ratchet = GetOrCreateOutboundRatchet();
        var (key, nonce, gen) = ratchet.NextKey();
        try
        {
            return ApplicationMessageCodec.Encode(
                groupId: Context.GroupId,
                epoch: Context.Epoch,
                senderLeaf: LocalLeafIndex,
                generation: gen,
                key: key,
                nonce: nonce,
                plaintext: plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    /// <summary>
    /// Decrypts an application message produced by
    /// <see cref="EncryptApplicationMessage"/>. Enforces replay protection:
    /// a message whose generation has already been processed throws
    /// <see cref="CryptographicException"/>.
    /// </summary>
    public ApplicationMessage DecryptApplicationMessage(ReadOnlySpan<byte> mlsMessageBytes)
    {
        if (MemberLeaf is null)
        {
            throw new InvalidOperationException(
                "Application messages require a 2-member group. Run AddMember (or JoinFromWelcome) first.");
        }

        // Peek the header to learn the sender + generation before decrypting.
        // (The codec parses the header for us during Decode but we need the
        // generation to advance the right ratchet.)
        var rPeek = new NostrNet.Marmot.Encoding.TlsReader(mlsMessageBytes);
        ushort wireFormat = rPeek.ReadUInt16BigEndian();
        if (wireFormat != ApplicationMessageCodec.WireFormat)
        {
            throw new InvalidDataException(
                $"Unknown application-message wire format 0x{wireFormat:X4}.");
        }

        var senderGroupId = rPeek.ReadOpaqueVarInt();
        if (!senderGroupId.SequenceEqual(Context.GroupId))
        {
            throw new CryptographicException("Application message group_id does not match the current group.");
        }

        ulong epoch = rPeek.ReadUInt64BigEndian();
        if (epoch != Context.Epoch)
        {
            throw new CryptographicException(
                $"Application message epoch {epoch} does not match the current epoch {Context.Epoch}.");
        }

        uint senderLeaf = rPeek.ReadUInt32BigEndian();
        if (senderLeaf != PeerLeafIndex)
        {
            throw new CryptographicException(
                $"Application message claims to be from leaf {senderLeaf}, but expected peer leaf {PeerLeafIndex}.");
        }

        uint generation = rPeek.ReadUInt32BigEndian();
        if (generation <= _highestSeenInboundGeneration)
        {
            throw new CryptographicException(
                $"Replay rejected: generation {generation} ≤ already-seen {_highestSeenInboundGeneration}.");
        }

        var ratchet = GetOrCreateInboundRatchet();
        var (key, nonce) = ratchet.KeyForGeneration(generation);
        try
        {
            var msg = ApplicationMessageCodec.Decode(mlsMessageBytes, key, nonce);
            _highestSeenInboundGeneration = generation;
            return msg;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    /// <summary>
    /// Founder bootstrap. Creates a new group with the founder as the
    /// sole member at epoch 0, then immediately rolls the key schedule
    /// forward so <see cref="Secrets"/> describes epoch 0.
    /// </summary>
    public static ReferenceMlsGroup CreateAsFounder(
        byte[] groupId,
        BasicCredential founderCredential,
        byte[] founderSignaturePublicKey,
        byte[] founderSignaturePrivateKey,
        byte[] founderInitPublicKey,
        byte[] founderInitPrivateKey,
        byte[] founderEncryptionPublicKey)
    {
        ArgumentNullException.ThrowIfNull(groupId);
        if (groupId.Length == 0)
        {
            throw new ArgumentException("Group id must be non-empty.", nameof(groupId));
        }

        var caps = DefaultCapabilities();
        var lifetime = new Lifetime(0UL, ulong.MaxValue);

        var founderLeaf = LeafNode.Sign(
            encryptionKey: founderEncryptionPublicKey,
            signatureKey: founderSignaturePublicKey,
            signaturePrivateKey: founderSignaturePrivateKey,
            credential: founderCredential,
            capabilities: caps,
            lifetime: lifetime,
            extensions: Array.Empty<Extension>());

        // Epoch 0: only the founder. Tree hash is the leaf hash directly.
        byte[] treeHash0 = TreeHash.LeafHash(founderLeaf);
        var ctx0 = new GroupContext
        {
            Version = ProtocolVersion.Mls10,
            Ciphersuite = CiphersuiteInfo.Supported,
            GroupId = groupId,
            Epoch = 0UL,
            TreeHash = treeHash0,
            ConfirmedTranscriptHash = Array.Empty<byte>(),
            Extensions = Array.Empty<Extension>(),
        };

        // Bootstrap epoch 0 with a random "init_secret_[-1]" and a zero commit_secret.
        byte[] bootstrapInit = new byte[CiphersuiteInfo.Nh];
        RandomNumberGenerator.Fill(bootstrapInit);
        EpochSecrets secrets0;
        try
        {
            secrets0 = KeySchedule.Derive(bootstrapInit, ZerosNh, ctx0.Encode());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bootstrapInit);
        }

        return new ReferenceMlsGroup(
            context: ctx0,
            secrets: secrets0,
            founderLeaf: founderLeaf,
            memberLeaf: null,
            founderSignatureSk: founderSignaturePrivateKey,
            founderInitSk: founderInitPrivateKey,
            memberInitSk: null);
    }

    /// <summary>
    /// Adds a single member to a group of size 1, producing the Welcome
    /// bytes Marmot kind-444 will deliver. The group advances to epoch 1.
    /// </summary>
    public byte[] AddMember(KeyPackage memberKeyPackage)
    {
        ArgumentNullException.ThrowIfNull(memberKeyPackage);
        if (MemberLeaf is not null)
        {
            throw new NotSupportedException("Reference provider only supports adding the second member to a 1-member group.");
        }

        if (memberKeyPackage.Ciphersuite != CiphersuiteInfo.Supported)
        {
            throw new NotSupportedException(
                $"KeyPackage ciphersuite 0x{(ushort)memberKeyPackage.Ciphersuite:X4} != supported 0x{(ushort)CiphersuiteInfo.Supported:X4}.");
        }

        if (!memberKeyPackage.Verify())
        {
            throw new CryptographicException("New member's KeyPackage signature failed verification.");
        }

        var memberLeaf = memberKeyPackage.Leaf;
        byte[] tree1Hash = TreeHash.HashTwoMemberTree(FounderLeaf, memberLeaf);

        var ctx1 = new GroupContext
        {
            Version = Context.Version,
            Ciphersuite = Context.Ciphersuite,
            GroupId = Context.GroupId,
            Epoch = Context.Epoch + 1,
            TreeHash = tree1Hash,
            ConfirmedTranscriptHash = Array.Empty<byte>(),
            Extensions = Array.Empty<Extension>(),
        };

        // Roll the key schedule forward with init_secret_next from the prior epoch
        // and zero commit_secret (no UpdatePath, single Add proposal).
        byte[] initSecretPrev = Secrets.InitSecretNext;
        EpochSecrets secrets1 = KeySchedule.Derive(initSecretPrev, ZerosNh, ctx1.Encode());

        // Build GroupInfo with founder's leaf inlined for joiner-side leaf signature check.
        byte[] confirmationTag = ConfirmationTag(secrets1.ConfirmationKey, ctx1.ConfirmedTranscriptHash);
        var groupInfo = GroupInfo.Sign(
            groupContext: ctx1,
            extensions: new[] { new Extension(FounderLeafExtensionType, FounderLeaf.Encode()) },
            confirmationTag: confirmationTag,
            signerLeafIndex: 0,
            signerPrivateKey: FounderSignatureSk);

        // encrypted_group_info = AEAD(welcome_key, welcome_nonce, "", encoded GroupInfo)
        byte[] groupInfoBytes = groupInfo.Encode();
        byte[] encryptedGroupInfo = new byte[groupInfoBytes.Length + CiphersuiteInfo.Nt];
        using (var aead = new AesGcm(secrets1.WelcomeKey, CiphersuiteInfo.Nt))
        {
            aead.Encrypt(
                secrets1.WelcomeNonce,
                groupInfoBytes,
                encryptedGroupInfo.AsSpan(0, groupInfoBytes.Length),
                encryptedGroupInfo.AsSpan(groupInfoBytes.Length, CiphersuiteInfo.Nt),
                associatedData: ReadOnlySpan<byte>.Empty);
        }

        // GroupSecrets plaintext.
        var groupSecrets = new GroupSecrets(secrets1.JoinerSecret, PathSecret: null);
        byte[] groupSecretsBytes = groupSecrets.Encode();

        // HPKE-seal GroupSecrets to the recipient's init_key.
        // info = encrypted_group_info bytes. See the long comment in
        // JoinFromWelcome for why we use this and not encoded(GroupContext):
        // it lets the joiner do HPKE.Open before reconstructing the
        // GroupContext.
        var (kemOut, ct) = Hpke.Seal(
            recipientPublicKey: memberKeyPackage.InitKey,
            info: encryptedGroupInfo,
            aad: ReadOnlySpan<byte>.Empty,
            plaintext: groupSecretsBytes);

        byte[] kpRef = memberKeyPackage.ComputeReference();
        var welcome = new Welcome
        {
            Ciphersuite = ctx1.Ciphersuite,
            Secrets = new[] { new EncryptedGroupSecrets(kpRef, new HpkeCiphertext(kemOut, ct)) },
            EncryptedGroupInfo = encryptedGroupInfo,
        };

        // Commit local state to epoch 1.
        Context = ctx1;
        Secrets = secrets1;
        MemberLeaf = memberLeaf;

        return welcome.Encode();
    }

    /// <summary>
    /// Joins a group by processing a Welcome message. The local side
    /// must have a signature keypair already (used solely to populate
    /// <see cref="FounderSignatureSk"/> — unused by the reference
    /// provider after join since we don't sign anything else).
    /// </summary>
    /// <param name="welcomeBytes">Serialized Welcome from <see cref="AddMember"/>.</param>
    /// <param name="myKeyPackage">The recipient's KeyPackage (so we can match the EncryptedGroupSecrets entry).</param>
    /// <param name="myInitPrivateKey">HPKE init private key (matching <c>myKeyPackage.InitKey</c>).</param>
    /// <param name="mySignaturePrivateKey">Ed25519 signature private key matching the recipient's leaf signature key.</param>
    public static ReferenceMlsGroup JoinFromWelcome(
        byte[] welcomeBytes,
        KeyPackage myKeyPackage,
        byte[] myInitPrivateKey,
        byte[] mySignaturePrivateKey)
    {
        ArgumentNullException.ThrowIfNull(welcomeBytes);
        ArgumentNullException.ThrowIfNull(myKeyPackage);
        ArgumentNullException.ThrowIfNull(myInitPrivateKey);
        ArgumentNullException.ThrowIfNull(mySignaturePrivateKey);

        var welcome = Welcome.Decode(welcomeBytes);
        if (welcome.Ciphersuite != CiphersuiteInfo.Supported)
        {
            throw new NotSupportedException($"Welcome ciphersuite 0x{(ushort)welcome.Ciphersuite:X4} not supported.");
        }

        // Locate our entry by KeyPackageRef.
        byte[] myRef = myKeyPackage.ComputeReference();
        EncryptedGroupSecrets? mine = null;
        for (int i = 0; i < welcome.Secrets.Count; i++)
        {
            if (CryptographicOperations.FixedTimeEquals(welcome.Secrets[i].NewMember, myRef))
            {
                mine = welcome.Secrets[i];
                break;
            }
        }

        if (mine is null)
        {
            throw new CryptographicException("Welcome does not contain an EncryptedGroupSecrets entry for this KeyPackage.");
        }

        // The HPKE info parameter is the new epoch's GroupContext. We
        // don't know its bytes yet — we'll need to compute it after we've
        // decrypted the GroupInfo and reconstructed the tree. So decrypt
        // in two steps: first HPKE-decrypt with a hypothesis (we will
        // need to verify after).
        //
        // We avoid that recursion by following the joiner-side trick:
        // - HPKE info is the encoded GroupContext from GroupInfo. But the
        //   GroupInfo is in encrypted_group_info, encrypted by welcome_key
        //   derived from joiner_secret.
        // - joiner_secret is in encrypted_group_secrets, encrypted with
        //   info=GroupContext.
        //
        // The way this works in practice: the joiner doesn't actually need
        // to verify the HPKE info on decrypt (HPKE doesn't reveal info to
        // the receiver — it's just mixed in). The receiver simply runs
        // HPKE.Open with the SAME info bytes the sender used. So we need
        // to compute the encoded GroupContext from what we'll discover.
        //
        // To avoid that chicken-and-egg, the receiver:
        //   1. HPKE-decrypts using info = <to be determined>.
        //
        // We instead use the well-known shortcut: try with a guessed empty
        // info — that won't match. Real implementations bind GroupContext
        // into HPKE info; this means the joiner must FIRST reconstruct
        // GroupContext from elsewhere.
        //
        // For our reference provider we adopt this convention: HPKE info
        // for encrypted_group_secrets is the WELCOME's encrypted_group_info
        // bytes. That gives the joiner a bytestring it has immediately on
        // hand, sidesteps the recursion, and is the convention used by
        // several MLS implementations (e.g. openmls's "encrypted_group_info
        // as HPKE info" extension) for the welcome leg.
        byte[] hpkeInfo = welcome.EncryptedGroupInfo;

        byte[] groupSecretsBytes = Hpke.Open(
            enc: mine.EncryptedSecrets.KemOutput,
            recipientPrivateKey: myInitPrivateKey,
            info: hpkeInfo,
            aad: ReadOnlySpan<byte>.Empty,
            ciphertext: mine.EncryptedSecrets.Ciphertext);

        var groupSecrets = GroupSecrets.Decode(groupSecretsBytes);
        byte[] joinerSecret = groupSecrets.JoinerSecret;

        // Derive welcome_key/nonce from joiner_secret.
        var partial = KeySchedule.DeriveFromJoinerSecret(joinerSecret, ReadOnlySpan<byte>.Empty);
        // partial isn't quite right because we don't know GroupContext bytes yet.
        // But welcome_key/nonce derivations only depend on joiner_secret, NOT on
        // GroupContext. So partial.WelcomeKey/.WelcomeNonce are valid.
        byte[] welcomeKey = partial.WelcomeKey;
        byte[] welcomeNonce = partial.WelcomeNonce;

        // Decrypt GroupInfo.
        if (welcome.EncryptedGroupInfo.Length < CiphersuiteInfo.Nt)
        {
            throw new CryptographicException("encrypted_group_info is shorter than the AEAD tag.");
        }

        int infoCtLen = welcome.EncryptedGroupInfo.Length - CiphersuiteInfo.Nt;
        byte[] groupInfoBytes = new byte[infoCtLen];
        using (var aead = new AesGcm(welcomeKey, CiphersuiteInfo.Nt))
        {
            aead.Decrypt(
                welcomeNonce,
                welcome.EncryptedGroupInfo.AsSpan(0, infoCtLen),
                welcome.EncryptedGroupInfo.AsSpan(infoCtLen, CiphersuiteInfo.Nt),
                groupInfoBytes,
                associatedData: ReadOnlySpan<byte>.Empty);
        }

        var groupInfo = GroupInfo.Decode(groupInfoBytes);

        // Locate the founder's leaf in GroupInfo extensions and verify it.
        Extension? founderLeafExt = null;
        for (int i = 0; i < groupInfo.Extensions.Count; i++)
        {
            if (groupInfo.Extensions[i].ExtensionType == FounderLeafExtensionType)
            {
                founderLeafExt = groupInfo.Extensions[i];
                break;
            }
        }

        if (founderLeafExt is null)
        {
            throw new CryptographicException("GroupInfo is missing the founder-leaf extension.");
        }

        var founderLeaf = LeafNode.Decode(founderLeafExt.Data);
        if (!founderLeaf.VerifySignature())
        {
            throw new CryptographicException("Founder leaf signature is invalid.");
        }

        if (groupInfo.Signer != 0)
        {
            throw new CryptographicException(
                $"Reference provider only supports founder-signed GroupInfo (signer = 0); got {groupInfo.Signer}.");
        }

        if (!groupInfo.VerifySignature(founderLeaf.SignatureKey))
        {
            throw new CryptographicException("GroupInfo signature is invalid.");
        }

        // Verify tree_hash matches what we'd compute.
        byte[] expectedTreeHash = TreeHash.HashTwoMemberTree(founderLeaf, myKeyPackage.Leaf);
        if (!CryptographicOperations.FixedTimeEquals(expectedTreeHash, groupInfo.GroupContext.TreeHash))
        {
            throw new CryptographicException("tree_hash in GroupInfo does not match the locally computed tree hash.");
        }

        // Now compute the actual epoch secrets using the verified GroupContext.
        EpochSecrets secrets = KeySchedule.DeriveFromJoinerSecret(joinerSecret, groupInfo.GroupContext.Encode());

        // Verify confirmation_tag.
        byte[] expectedTag = ConfirmationTag(secrets.ConfirmationKey, groupInfo.GroupContext.ConfirmedTranscriptHash);
        if (!CryptographicOperations.FixedTimeEquals(expectedTag, groupInfo.ConfirmationTag))
        {
            throw new CryptographicException("confirmation_tag is invalid.");
        }

        return new ReferenceMlsGroup(
            context: groupInfo.GroupContext,
            secrets: secrets,
            founderLeaf: founderLeaf,
            memberLeaf: myKeyPackage.Leaf,
            founderSignatureSk: mySignaturePrivateKey,
            founderInitSk: null,
            memberInitSk: myInitPrivateKey);
    }

    private static byte[] ConfirmationTag(byte[] confirmationKey, ReadOnlySpan<byte> confirmedTranscriptHash)
    {
        return HMACSHA256.HashData(confirmationKey, confirmedTranscriptHash);
    }

    /// <summary>The default capabilities advertised by leaves in this reference provider.</summary>
    public static Capabilities DefaultCapabilities() => new(
        Versions: new ushort[] { (ushort)ProtocolVersion.Mls10 },
        CipherSuites: new ushort[] { (ushort)CiphersuiteInfo.Supported },
        ExtensionTypes: new ushort[] { FounderLeafExtensionType },
        ProposalTypes: Array.Empty<ushort>(),
        CredentialTypes: new ushort[] { (ushort)CredentialType.Basic });
}
