// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ceremony's file bodies, and [`Authenticated`]: a body from the
//! member a file names, made only by [`import`] (brief §3, §3A).
//!
//! Every body is self-describing and bounded: a per-input list leads with
//! its input count (`1..=MAX_INPUTS`), a per-signer list with its count
//! (`≤ MAX_MULTISIG_PARTICIPANTS`), and every length is checked before
//! anything is read. A preprocess (64 bytes) and a share (32 bytes) travel
//! as raw bytes and are decoded by the receiver's machine, which knows the
//! algorithm's generators; a per-output key and a hybrid signature are
//! parsed here, canonically.
//!
//! ```text
//! Proposal       = u32(len) ‖ intent ‖ n ‖ n × (preprocess(64) ‖ key(1996))
//! Commitment     = n ‖ n × (preprocess(64) ‖ key(1996))
//! SigningSet     = k ‖ k × (u32(len) ‖ sealed file)
//! ResponderShare = n ‖ n × (preprocess(64) ‖ share(32) ‖ key(1996))
//! SignatureShare = n ‖ n × share(32)
//! FinalTx        = u32(len) ‖ sealed Proposal file ‖ n ‖ m ‖ n × m × key(1996)
//!                  ‖ u32(len) ‖ FCMP++ proof ‖ u32(len) ‖ range proof
//! HybridSig      = n ‖ n × signature(3385)
//! ```

use rand::{CryptoRng, RngCore};
use shekyl_address::multisig_address::MAX_MULTISIG_PARTICIPANTS;
use shekyl_crypto_pq::signature::{HybridPublicKey, HybridSignature};
use shekyl_fcmp::frost_sal::{SAL_PREPROCESS_LEN, SAL_SHARE_LEN};
use shekyl_network::NetworkId;

use crate::envelope::{open_envelope, seal_envelope, ImportRefusal, SealError, MAX_FILE_LEN};
use crate::intent::{SpendIntent, MAX_INPUTS};
use crate::member_file::MemberFile;
use crate::messages::MessageType;

/// A per-output public key's length.
pub const KEY_LEN: usize = HybridPublicKey::CANONICAL_LEN;
/// A hybrid signature's length.
pub const SIGNATURE_LEN: usize = HybridSignature::CANONICAL_LEN;

/// Why a body does not parse. Each names the field.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the {body} body does not parse at '{field}'")]
pub struct BodyError {
    /// Which body.
    pub body: &'static str,
    /// Which field.
    pub field: &'static str,
}

struct Reader<'a> {
    bytes: &'a [u8],
    body: &'static str,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], body: &'static str) -> Self {
        Self { bytes, body }
    }

    fn err(&self, field: &'static str) -> BodyError {
        BodyError {
            body: self.body,
            field,
        }
    }

    fn take(&mut self, n: usize, field: &'static str) -> Result<&'a [u8], BodyError> {
        if self.bytes.len() < n {
            return Err(self.err(field));
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(head)
    }

    fn arr<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N], BodyError> {
        Ok(self.take(N, field)?.try_into().expect("N bytes"))
    }

    fn len(&mut self, max: usize, field: &'static str) -> Result<usize, BodyError> {
        let n =
            usize::try_from(u32::from_le_bytes(self.arr(field)?)).map_err(|_| self.err(field))?;
        if n > max {
            return Err(self.err(field));
        }
        Ok(n)
    }

    fn count(&mut self, min: usize, max: usize, field: &'static str) -> Result<usize, BodyError> {
        let n = usize::from(self.arr::<1>(field)?[0]);
        if n < min || n > max {
            return Err(self.err(field));
        }
        Ok(n)
    }

    fn inputs(&mut self) -> Result<usize, BodyError> {
        self.count(1, MAX_INPUTS as usize, "input count")
    }

    fn key(&mut self) -> Result<HybridPublicKey, BodyError> {
        HybridPublicKey::from_canonical_bytes(self.take(KEY_LEN, "key")?)
            .map_err(|_| self.err("key"))
    }

    fn signature(&mut self) -> Result<HybridSignature, BodyError> {
        HybridSignature::from_canonical_bytes(self.take(SIGNATURE_LEN, "signature")?)
            .map_err(|_| self.err("signature"))
    }

    fn finish(self) -> Result<(), BodyError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(self.err("trailing bytes"))
        }
    }
}

fn push_len(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("a body field is bounded by the file size")
            .to_le_bytes(),
    );
    out.extend_from_slice(bytes);
}

fn push_count(out: &mut Vec<u8>, n: usize) {
    out.push(u8::try_from(n).expect("a count is bounded by its cap"));
}

fn key_bytes(key: &HybridPublicKey) -> Vec<u8> {
    key.to_canonical_bytes()
        .expect("a parsed or derived key encodes")
}

/// A member's first-round contribution for one input: its preprocess, and
/// its per-output public key (brief P-1).
#[derive(Clone)]
pub struct RoundOne {
    /// The preprocess, as its machine wrote it.
    pub preprocess: [u8; SAL_PREPROCESS_LEN],
    /// The member's per-output public key for this input.
    pub key: HybridPublicKey,
}

impl RoundOne {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.preprocess);
        out.extend_from_slice(&key_bytes(&self.key));
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, BodyError> {
        Ok(Self {
            preprocess: r.arr("preprocess")?,
            key: r.key()?,
        })
    }
}

/// A file body: its type, its encoding and its exact decoding.
pub trait Body: Sized {
    /// The message type it travels as.
    const TYPE: MessageType;
    /// The bytes.
    fn encode(&self) -> Vec<u8>;
    /// Parse exactly.
    ///
    /// # Errors
    ///
    /// [`BodyError`] naming the field that does not parse.
    fn decode(bytes: &[u8]) -> Result<Self, BodyError>;
}

/// Step 1: the intent, and the proposer's first round per input.
pub struct Proposal {
    /// The intent.
    pub intent: SpendIntent,
    /// The proposer's first round, per input.
    pub rounds: Vec<RoundOne>,
}

impl Body for Proposal {
    const TYPE: MessageType = MessageType::Proposal;

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_len(
            &mut out,
            &self
                .intent
                .to_canonical_bytes()
                .expect("a validated intent encodes"),
        );
        push_count(&mut out, self.rounds.len());
        for round in &self.rounds {
            round.write(&mut out);
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, BodyError> {
        let mut r = Reader::new(bytes, "Proposal");
        let len = r.len(MAX_FILE_LEN, "intent")?;
        let intent = SpendIntent::from_canonical_bytes(r.take(len, "intent")?)
            .map_err(|_| r.err("intent"))?;
        let n = r.inputs()?;
        let rounds = (0..n)
            .map(|_| RoundOne::read(&mut r))
            .collect::<Result<_, _>>()?;
        r.finish()?;
        Ok(Self { intent, rounds })
    }
}

/// Step 2: a holder's first round per input.
pub struct Commitment {
    /// The holder's first round, per input.
    pub rounds: Vec<RoundOne>,
}

impl Body for Commitment {
    const TYPE: MessageType = MessageType::Commitment;

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_count(&mut out, self.rounds.len());
        for round in &self.rounds {
            round.write(&mut out);
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, BodyError> {
        let mut r = Reader::new(bytes, "Commitment");
        let n = r.inputs()?;
        let rounds = (0..n)
            .map(|_| RoundOne::read(&mut r))
            .collect::<Result<_, _>>()?;
        r.finish()?;
        Ok(Self { rounds })
    }
}

/// Steps 3 and 5: other members' files, forwarded sealed as received
/// (brief P-2), so each is checked under its own sender's signature.
pub struct SigningSet {
    /// The forwarded files.
    pub files: Vec<Vec<u8>>,
}

impl Body for SigningSet {
    const TYPE: MessageType = MessageType::SigningSet;

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_count(&mut out, self.files.len());
        for file in &self.files {
            push_len(&mut out, file);
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, BodyError> {
        let mut r = Reader::new(bytes, "SigningSet");
        let k = r.count(1, usize::from(MAX_MULTISIG_PARTICIPANTS), "file count")?;
        let files = (0..k)
            .map(|_| {
                let len = r.len(MAX_FILE_LEN, "file")?;
                Ok(r.take(len, "file")?.to_vec())
            })
            .collect::<Result<_, BodyError>>()?;
        r.finish()?;
        Ok(Self { files })
    }
}

/// Step 4: the responder's first round and share per input.
pub struct ResponderShare {
    /// Per input: the responder's first round and its share.
    pub inputs: Vec<(RoundOne, [u8; SAL_SHARE_LEN])>,
}

impl Body for ResponderShare {
    const TYPE: MessageType = MessageType::ResponderShare;

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_count(&mut out, self.inputs.len());
        for (round, share) in &self.inputs {
            out.extend_from_slice(&round.preprocess);
            out.extend_from_slice(share);
            out.extend_from_slice(&key_bytes(&round.key));
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, BodyError> {
        let mut r = Reader::new(bytes, "ResponderShare");
        let n = r.inputs()?;
        let inputs = (0..n)
            .map(|_| {
                let preprocess = r.arr("preprocess")?;
                let share = r.arr("share")?;
                let key = r.key()?;
                Ok((RoundOne { preprocess, key }, share))
            })
            .collect::<Result<_, BodyError>>()?;
        r.finish()?;
        Ok(Self { inputs })
    }
}

/// Step 6: a holder's share per input.
pub struct SignatureShare {
    /// The holder's share, per input.
    pub shares: Vec<[u8; SAL_SHARE_LEN]>,
}

impl Body for SignatureShare {
    const TYPE: MessageType = MessageType::SignatureShare;

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_count(&mut out, self.shares.len());
        for share in &self.shares {
            out.extend_from_slice(share);
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, BodyError> {
        let mut r = Reader::new(bytes, "SignatureShare");
        let n = r.inputs()?;
        let shares = (0..n).map(|_| r.arr("share")).collect::<Result<_, _>>()?;
        r.finish()?;
        Ok(Self { shares })
    }
}

/// Step 8: what a signer cannot compute itself: the proofs, and every
/// signer's per-output key per input. The `Proposal` file rides along so a
/// member that kept no state can rebuild its context (brief P-3).
pub struct FinalTx {
    /// The proposer's `Proposal` file, sealed as sent.
    pub proposal_file: Vec<u8>,
    /// Per input, every signer's per-output key in the intent's signer
    /// order.
    pub keys: Vec<Vec<HybridPublicKey>>,
    /// The FCMP++ proof, SALs included.
    pub fcmp_proof: Vec<u8>,
    /// The range proof over the outputs.
    pub range_proof: Vec<u8>,
}

impl Body for FinalTx {
    const TYPE: MessageType = MessageType::FinalTx;

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_len(&mut out, &self.proposal_file);
        push_count(&mut out, self.keys.len());
        push_count(&mut out, self.keys.first().map_or(0, Vec::len));
        for input in &self.keys {
            for key in input {
                out.extend_from_slice(&key_bytes(key));
            }
        }
        push_len(&mut out, &self.fcmp_proof);
        push_len(&mut out, &self.range_proof);
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, BodyError> {
        let mut r = Reader::new(bytes, "FinalTx");
        let len = r.len(MAX_FILE_LEN, "proposal file")?;
        let proposal_file = r.take(len, "proposal file")?.to_vec();
        let n = r.inputs()?;
        let m = r.count(2, usize::from(MAX_MULTISIG_PARTICIPANTS), "signer count")?;
        let keys = (0..n)
            .map(|_| (0..m).map(|_| r.key()).collect::<Result<_, _>>())
            .collect::<Result<_, _>>()?;
        let len = r.len(MAX_FILE_LEN, "fcmp proof")?;
        let fcmp_proof = r.take(len, "fcmp proof")?.to_vec();
        let len = r.len(MAX_FILE_LEN, "range proof")?;
        let range_proof = r.take(len, "range proof")?.to_vec();
        r.finish()?;
        Ok(Self {
            proposal_file,
            keys,
            fcmp_proof,
            range_proof,
        })
    }
}

/// Step 9: a signer's hybrid signature per input.
pub struct HybridSig {
    /// The signer's hybrid signature, per input.
    pub signatures: Vec<HybridSignature>,
}

impl Body for HybridSig {
    const TYPE: MessageType = MessageType::HybridSig;

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_count(&mut out, self.signatures.len());
        for sig in &self.signatures {
            out.extend_from_slice(
                &sig.to_canonical_bytes()
                    .expect("a made or parsed signature encodes"),
            );
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, BodyError> {
        let mut r = Reader::new(bytes, "HybridSig");
        let n = r.inputs()?;
        let signatures = (0..n).map(|_| r.signature()).collect::<Result<_, _>>()?;
        r.finish()?;
        Ok(Self { signatures })
    }
}

/// A body from the member its file names: the envelope opened under this
/// wallet's group, its sender signature verified, its type the body's,
/// and the body parsed exactly. Made only by [`import`], so a step that
/// takes an `Authenticated<Commitment>` cannot be handed anything else.
pub struct Authenticated<B> {
    sender: u8,
    intent_hash: [u8; 32],
    body: B,
    file: Vec<u8>,
}

impl<B> Authenticated<B> {
    /// The member who sent it.
    #[must_use]
    pub fn sender(&self) -> u8 {
        self.sender
    }

    /// The intent it belongs to.
    #[must_use]
    pub fn intent_hash(&self) -> &[u8; 32] {
        &self.intent_hash
    }

    /// The body.
    #[must_use]
    pub fn body(&self) -> &B {
        &self.body
    }

    /// The file as received, for forwarding.
    #[must_use]
    pub fn file(&self) -> &[u8] {
        &self.file
    }
}

/// An imported file, by type.
pub enum Incoming {
    /// Step 1.
    Proposal(Authenticated<Proposal>),
    /// Step 2.
    Commitment(Authenticated<Commitment>),
    /// Steps 3 and 5.
    SigningSet(Authenticated<SigningSet>),
    /// Step 4.
    ResponderShare(Authenticated<ResponderShare>),
    /// Step 6.
    SignatureShare(Authenticated<SignatureShare>),
    /// Step 8.
    FinalTx(Authenticated<FinalTx>),
    /// Step 9.
    HybridSig(Authenticated<HybridSig>),
}

/// Why a file was refused on import.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// The envelope's own refusal (`envelope::open_envelope`).
    #[error(transparent)]
    Envelope(#[from] ImportRefusal),
    /// The body does not parse.
    #[error(transparent)]
    Body(#[from] BodyError),
    /// A `Proposal`'s intent does not hash to the intent hash its file
    /// carries.
    #[error("the proposal's intent is not the intent its file names")]
    ProposalIntent,
    /// A `Proposal` not sent by the intent's proposer.
    #[error("the proposal is not from the intent's proposer")]
    ProposalSender,
    /// A forwarded file names another intent than the file that carried it.
    #[error("a forwarded file is for another intent")]
    ForwardedIntent,
    /// A `SigningSet` forwarded inside a `SigningSet`.
    #[error("a forwarded file is itself a signing set")]
    NestedSigningSet,
}

fn authenticated<B: Body>(
    sender: u8,
    intent_hash: [u8; 32],
    body: &[u8],
    file: &[u8],
) -> Result<Authenticated<B>, ImportError> {
    Ok(Authenticated {
        sender,
        intent_hash,
        body: B::decode(body)?,
        file: file.to_vec(),
    })
}

/// Import `file` into a wallet whose groups are `groups`: open it, check
/// its sender's signature, parse its body by its type, and for a
/// `Proposal`, check that the intent hashes to the file's intent hash and
/// that the sender is its proposer. Returns the index of the group it is
/// for.
///
/// # Errors
///
/// [`ImportError`].
pub fn import(
    groups: &[&MemberFile],
    network_id: &NetworkId,
    file: &[u8],
) -> Result<(usize, Incoming), ImportError> {
    let opened = open_envelope(groups, network_id, file)?;
    let (s, h, b) = (
        opened.sender_index,
        opened.intent_hash,
        opened.body.as_slice(),
    );
    let incoming = match opened.message_type {
        MessageType::Proposal => {
            let proposal: Authenticated<Proposal> = authenticated(s, h, b, file)?;
            let intent = &proposal.body.intent;
            if intent.intent_hash().ok() != Some(h) {
                return Err(ImportError::ProposalIntent);
            }
            if intent.proposer_index != s {
                return Err(ImportError::ProposalSender);
            }
            Incoming::Proposal(proposal)
        }
        MessageType::Commitment => Incoming::Commitment(authenticated(s, h, b, file)?),
        MessageType::SigningSet => Incoming::SigningSet(authenticated(s, h, b, file)?),
        MessageType::ResponderShare => Incoming::ResponderShare(authenticated(s, h, b, file)?),
        MessageType::SignatureShare => Incoming::SignatureShare(authenticated(s, h, b, file)?),
        MessageType::FinalTx => Incoming::FinalTx(authenticated(s, h, b, file)?),
        MessageType::HybridSig => Incoming::HybridSig(authenticated(s, h, b, file)?),
    };
    Ok((opened.group, incoming))
}

/// Open one file forwarded inside a `SigningSet` or a `FinalTx`, for
/// `member`'s group: the same checks as [`import`], and the file must be
/// for `intent_hash` and must not itself be a `SigningSet`.
pub(crate) fn open_forwarded(
    member: &MemberFile,
    network_id: &NetworkId,
    intent_hash: &[u8; 32],
    file: &[u8],
) -> Result<Incoming, ImportError> {
    let (_, incoming) = import(&[member], network_id, file)?;
    let forwarded_intent = match &incoming {
        Incoming::SigningSet(_) => return Err(ImportError::NestedSigningSet),
        Incoming::Proposal(a) => a.intent_hash,
        Incoming::Commitment(a) => a.intent_hash,
        Incoming::ResponderShare(a) => a.intent_hash,
        Incoming::SignatureShare(a) => a.intent_hash,
        Incoming::FinalTx(a) => a.intent_hash,
        Incoming::HybridSig(a) => a.intent_hash,
    };
    if forwarded_intent != *intent_hash {
        return Err(ImportError::ForwardedIntent);
    }
    Ok(incoming)
}

/// Seal `body` as `member`'s file for `intent_hash`.
pub(crate) fn seal<B: Body>(
    member: &MemberFile,
    network_id: &NetworkId,
    intent_hash: &[u8; 32],
    body: &B,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<u8>, SealError> {
    seal_envelope(
        member,
        network_id,
        intent_hash,
        B::TYPE,
        &body.encode(),
        rng,
    )
}
