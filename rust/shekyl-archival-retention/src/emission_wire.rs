// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Byte-exact `txin_archival_reward_emission` wire (PR-E2).
//!
//! Freezes field set **(A)** of `REWARD_EMISSION_VIN_PLAN.md` §8.0.2 (pre-freeze
//! checks §8.0.3) — the `REWARD_EMISSION_LEG.md` §5.3 logical fields plus the two
//! **hybrid** (Ed25519 + ML-DSA-65) auths ratified in §8.0.1/Q1 and §5.3.1 (the
//! R1.A(2) ML-DSA-only line is retracted; each auth is a canonical
//! [`HybridSignature`] of exactly [`SINGLE_SIG_CANONICAL_LEN`] bytes).
//!
//! **Inert by construction (gate-last, §3.0):** this codec has no C++ caller and
//! the consensus whitelist (`check_inputs_types_supported`) default-rejects the
//! vin type on both the mempool and block paths until the C-1 activating merge.
//! Landing this module changes no consensus behavior.
//!
//! **Canonical-form discipline:** counts that must agree are carried **once** —
//! `reward_amount_plain` and the per-epoch work claims take their count from
//! `settlement_epochs`, and `WorkEpochClaim::epoch` is not carried on the wire
//! (readers reconstruct it from `settlement_epochs[i]`), so a misaligned or
//! epoch-mismatched encoding is *unrepresentable*, not merely rejected.
//!
//! [`HybridSignature`]: shekyl_crypto_pq::signature::HybridSignature

use core::fmt;
use std::io::{self, Read, Write};

use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};
use shekyl_curve_io::{read_byte, read_bytes, read_varint, write_varint};

use crate::bond_wire::{
    encode_holdings_descriptor, read_holdings_descriptor, HoldingsDescriptor, HoldingsKind,
    WireError as BondWireError, MAX_HOLDINGS_SHARDS,
};
use crate::hash::cshake256_64;
use crate::id::p_canonical_id_from_hybrid_pubkey;

/// Vin type tag: `txin_archival_reward_emission`.
///
/// Dense genesis tag scheme (`GENESIS_TX_WIRE_FORMAT.md` §tag registry;
/// `REWARD_EMISSION_VIN_PLAN.md` :118): `0x04` dense — the next free tag after
/// `gen 0x00`, `to_key 0x01`, `serve_credit 0x02`, `bond_post 0x03`. The C++
/// oracle's `VARIANT_TAG` is pinned `0x06` and lands with the C-1 dispatch, not
/// this codec.
pub const VIN_TYPE_ARCHIVAL_REWARD_EMISSION: u8 = 0x04;

/// Per-emission settlement-epoch batch cap (`REWARD_EMISSION_LEG.md` §5.3
/// `u64[MAX]`, `1 ≤ MAX ≤ 15`; the §6.6 F4 drain-vs-batch invariant is **signed**
/// at `W = 26`, batch `15`, `SEB = 10_000`).
pub const MAX_SETTLEMENT_EPOCHS_PER_EMISSION: usize = 15;

/// Structural DoS cap on the opaque `FcmpMembershipOnly` proof blob.
///
/// Not a consensus size rule — PR-E3's verify recomputes the exact expected
/// proof size for the (single-input, tree-depth) shape and rejects mismatches.
/// This bound only keeps a hostile length prefix from driving parser
/// allocation: the §10.1 sizing envelope puts the whole per-emission crypto
/// (proof + two auths + pubkeys) near 15 kB, so 64 KiB is ≥ 4× headroom.
pub const MAX_BACKING_PROOF_BYTES: usize = 65_536;

/// cSHAKE256 customization for the **stake-side** auth (`auth_backing`) binding
/// message. See [`ArchivalRewardEmissionVin::auth_msg`].
pub const EMISSION_AUTH_BACKING_CUSTOMIZATION: &[u8] = b"shekyl/archival-emission-auth-backing-v1";

/// cSHAKE256 customization for the **claim-side** auth (`auth_claim`) binding
/// message. See [`ArchivalRewardEmissionVin::auth_msg`].
pub const EMISSION_AUTH_CLAIM_CUSTOMIZATION: &[u8] = b"shekyl/archival-emission-auth-claim-v1";

/// Public per-shard work entry (`REWARD_EMISSION_LEG.md` §5.4) — the verifier
/// recomputes `work_P(E)` from archival state and demands equality with the
/// claim (integer-exact, tolerance zero).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardWorkEntry {
    /// Consensus shard identifier (gate 2).
    pub shard_id: u64,
    /// Must match the challenge state at `E`.
    pub serve_credit_bit: bool,
    /// Fixed-point scarcity × 1000 (integer recompute).
    pub scarcity_milli: u32,
}

/// Per-epoch public work breakdown (`REWARD_EMISSION_LEG.md` §5.4).
///
/// `epoch` is **not** carried on the wire — it is reconstructed from
/// `settlement_epochs[i]` at read, so an epoch-mismatched claim is
/// unrepresentable in the encoding. [`ArchivalRewardEmissionVin::write`] still
/// validates the in-memory struct's `epoch` against `settlement_epochs` so a
/// builder bug cannot silently reorder claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkEpochClaim {
    pub epoch: u64,
    /// Bounded by the holdings descriptor; wire-capped at [`MAX_HOLDINGS_SHARDS`].
    pub shard_entries: Vec<ShardWorkEntry>,
}

/// FCMP++ membership-only backing (`REWARD_EMISSION_LEG.md` §7.2; **no key
/// image** — anti-replay is the per-epoch dedup on the bond record).
///
/// Mirrors `shekyl_fcmp::proof::verify_membership_only`'s per-proof inputs minus
/// the verify-time context (`tree_root` comes from the tx's reference block;
/// `signable_tx_hash` is computed) — §8.0.2 lean (1). The full canonical hybrid
/// `backing_pubkey` rides the wire for the Auth-B leaf gate: verify recomputes
/// `hash_pqc_public_key(backing_pubkey)` and demands equality with
/// `pqc_pk_hash`, then verifies `auth_backing` under it
/// (`shekyl_emission_hybrid_auth_verify`, PR-E1).
///
/// **Reveal scope (§8.0.3 / §7.3):** the pubkey is per-output **one-time**, so
/// this reveal deterministically identifies exactly one backing output and
/// nothing else `P` owns; the §7.3 invariant (input-anonymity + cover
/// amount-decorrelation protect principal↔P, not output-hiding) plus the gate-6
/// GF-4b ladder/sweep make the reveal safe.
///
/// **Single-input pin.** The backing carries exactly **one** input. Gate 7's
/// bonds-only close deleted the `Σ amount ≥ ADMISSION_MIN` conjunct, so
/// "collectively satisfy" lost its purpose — one `P`-spendable output is a
/// complete backing statement. Structurally, keys are per-output one-time, so
/// `n` backing inputs would need `n` stake-side auths, contradicting the frozen
/// two-auth wire (§8.0.1/§10.1); and the GF-4b sweep design feeds exactly one
/// designated backing output (bond-post change at bootstrap, mint output at
/// steady state). A multi-input backing therefore reopens the §8.0.1 auth-arity
/// pin (rule 21), not just this struct. Bonus: the §8 open item 3
/// (backing-input distinctness) is vacuous at arity 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipOnlyBacking {
    /// Opaque `FcmpMembershipOnly` blob (`FCMP_MEMBERSHIP_ONLY.md` §3).
    pub proof: Vec<u8>,
    /// The rerandomized commitment `C~` (single input).
    pub pseudo_out: [u8; 32],
    /// The in-circuit committed leaf scalar `H(pqc_pk)` for the backing output.
    pub pqc_pk_hash: [u8; 32],
    /// Canonical hybrid (Ed25519 ‖ ML-DSA-65) public key of the backing output —
    /// exactly [`SINGLE_KEY_CANONICAL_LEN`] bytes; hashes to `pqc_pk_hash`.
    pub backing_pubkey: Vec<u8>,
    /// Layer count the proof was built at; verify checks it against the
    /// reference block's tree (`VerifyError::InvalidTreeRoot` on mismatch).
    pub tree_depth: u8,
}

/// `txin_archival_reward_emission` — frozen field set (A)
/// (`REWARD_EMISSION_VIN_PLAN.md` §8.0.2; wire order below is the freeze).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivalRewardEmissionVin {
    /// `P`'s canonical hybrid public key (`scheme_id = 1`), exactly
    /// [`SINGLE_KEY_CANONICAL_LEN`] bytes.
    pub p_pubkey: Vec<u8>,
    /// Must match the bond record after first emission (§5.3 / §6.4.1).
    pub holdings: HoldingsDescriptor,
    /// Claimed settlement epochs — strictly increasing (hence unique),
    /// `1..=`[`MAX_SETTLEMENT_EPOCHS_PER_EMISSION`] entries.
    pub settlement_epochs: Vec<u64>,
    /// Per-epoch work claims, aligned with `settlement_epochs`.
    pub work_claim: Vec<WorkEpochClaim>,
    /// FCMP++ membership-only backing (no key image).
    pub backing: MembershipOnlyBacking,
    /// Loud per-epoch mint amounts, aligned with `settlement_epochs`
    /// (§5.5 / §8.0.2 lean (2): per-epoch, not a single total — the tighter
    /// zero-tolerance economics compare).
    pub reward_amount_plain: Vec<u64>,
    /// Stake-side hybrid auth (`P`-that-staked ↔ bond; the C-1 gate verifies it
    /// against the backing leaf). Canonical [`SINGLE_SIG_CANONICAL_LEN`] bytes.
    pub auth_backing: Vec<u8>,
    /// Claim-side hybrid auth (`P`-that-claims ↔ this payout + epoch set;
    /// non-replayable). Canonical [`SINGLE_SIG_CANONICAL_LEN`] bytes.
    pub auth_claim: Vec<u8>,
}

/// One entry of the ordered reward vout commit set bound by the auth digest
/// (R1.A `reward_commit_set_digest`: destination binding survives any future
/// change to what the tx hash spans).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewardCommit {
    /// Output Pedersen commitment.
    pub commitment: [u8; 32],
    /// Loud output amount (§5.5).
    pub amount_plain: u64,
    /// Output one-time key.
    pub one_time_key: [u8; 32],
}

/// Which of the two Q1 auths a binding message is for. Distinct cSHAKE
/// customizations make the two messages domain-separated **by construction**
/// (Q1: "two distinct binding messages, not one signature checked twice") while
/// both inherit the full R1.A commitment inventory from the one shared builder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmissionAuthRole {
    Backing,
    Claim,
}

#[derive(Debug)]
pub enum WireError {
    Io(io::Error),
    UnknownVinType(u8),
    /// A hybrid public key field is not exactly the canonical length.
    PubkeyLenNotCanonical {
        field: &'static str,
        got: usize,
    },
    /// A hybrid signature field is not exactly the canonical length.
    SigLenNotCanonical {
        field: &'static str,
        got: usize,
    },
    EpochCountOutOfRange {
        got: usize,
    },
    EpochsNotStrictlyIncreasing,
    /// In-memory struct misalignment caught on write (unrepresentable on wire).
    RewardAmountsMisaligned {
        epochs: usize,
        amounts: usize,
    },
    /// In-memory struct misalignment caught on write (unrepresentable on wire).
    WorkClaimMisaligned {
        epochs: usize,
        claims: usize,
    },
    /// In-memory `WorkEpochClaim::epoch` disagrees with `settlement_epochs`.
    WorkClaimEpochMismatch {
        index: usize,
        expected: u64,
        got: u64,
    },
    ShardEntriesExceeded {
        got: usize,
    },
    InvalidServeCreditBit(u8),
    ScarcityOverflow(u64),
    ProofSizeInvalid {
        got: usize,
    },
    Holdings(BondWireError),
    TrailingBytes,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::UnknownVinType(t) => write!(f, "unknown archival vin type {t}"),
            Self::PubkeyLenNotCanonical { field, got } => {
                write!(f, "{field} length {got} != canonical hybrid pubkey length")
            }
            Self::SigLenNotCanonical { field, got } => {
                write!(
                    f,
                    "{field} length {got} != canonical hybrid signature length"
                )
            }
            Self::EpochCountOutOfRange { got } => {
                write!(
                    f,
                    "settlement epoch count {got} outside 1..={MAX_SETTLEMENT_EPOCHS_PER_EMISSION}"
                )
            }
            Self::EpochsNotStrictlyIncreasing => {
                write!(f, "settlement epochs must be strictly increasing")
            }
            Self::RewardAmountsMisaligned { epochs, amounts } => {
                write!(
                    f,
                    "reward amounts ({amounts}) misaligned with epochs ({epochs})"
                )
            }
            Self::WorkClaimMisaligned { epochs, claims } => {
                write!(
                    f,
                    "work claims ({claims}) misaligned with epochs ({epochs})"
                )
            }
            Self::WorkClaimEpochMismatch {
                index,
                expected,
                got,
            } => write!(
                f,
                "work claim {index} epoch {got} != settlement epoch {expected}"
            ),
            Self::ShardEntriesExceeded { got } => {
                write!(f, "shard work entry count {got} exceeds bound")
            }
            Self::InvalidServeCreditBit(b) => write!(f, "invalid serve_credit bit {b}"),
            Self::ScarcityOverflow(v) => write!(f, "scarcity_milli {v} exceeds u32"),
            Self::ProofSizeInvalid { got } => {
                write!(
                    f,
                    "backing proof length {got} outside 1..={MAX_BACKING_PROOF_BYTES}"
                )
            }
            Self::Holdings(e) => write!(f, "holdings: {e}"),
            Self::TrailingBytes => write!(f, "trailing bytes after emission payload"),
        }
    }
}

impl std::error::Error for WireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Holdings(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for WireError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<BondWireError> for WireError {
    fn from(e: BondWireError) -> Self {
        match e {
            BondWireError::Io(io) => Self::Io(io),
            other => Self::Holdings(other),
        }
    }
}

fn strictly_increasing(epochs: &[u64]) -> bool {
    epochs.windows(2).all(|w| w[0] < w[1])
}

fn read_canonical_pubkey<R: Read>(r: &mut R, field: &'static str) -> Result<Vec<u8>, WireError> {
    let len: usize = read_varint(r)?;
    if len != SINGLE_KEY_CANONICAL_LEN {
        return Err(WireError::PubkeyLenNotCanonical { field, got: len });
    }
    let mut key = vec![0u8; len];
    r.read_exact(&mut key)?;
    Ok(key)
}

fn read_canonical_sig<R: Read>(r: &mut R, field: &'static str) -> Result<Vec<u8>, WireError> {
    let len: usize = read_varint(r)?;
    if len != SINGLE_SIG_CANONICAL_LEN {
        return Err(WireError::SigLenNotCanonical { field, got: len });
    }
    let mut sig = vec![0u8; len];
    r.read_exact(&mut sig)?;
    Ok(sig)
}

impl ArchivalRewardEmissionVin {
    /// Structural invariants shared by [`Self::write`] (in-memory struct may be
    /// inconsistent) and documented for readers ([`Self::read_payload`] enforces
    /// the same set inline, before allocation, as it parses).
    pub fn validate(&self) -> Result<(), WireError> {
        if self.p_pubkey.len() != SINGLE_KEY_CANONICAL_LEN {
            return Err(WireError::PubkeyLenNotCanonical {
                field: "P_pubkey",
                got: self.p_pubkey.len(),
            });
        }
        if self.backing.backing_pubkey.len() != SINGLE_KEY_CANONICAL_LEN {
            return Err(WireError::PubkeyLenNotCanonical {
                field: "backing_pubkey",
                got: self.backing.backing_pubkey.len(),
            });
        }
        for (field, sig) in [
            ("auth_backing", &self.auth_backing),
            ("auth_claim", &self.auth_claim),
        ] {
            if sig.len() != SINGLE_SIG_CANONICAL_LEN {
                return Err(WireError::SigLenNotCanonical {
                    field,
                    got: sig.len(),
                });
            }
        }
        let n = self.settlement_epochs.len();
        if n == 0 || n > MAX_SETTLEMENT_EPOCHS_PER_EMISSION {
            return Err(WireError::EpochCountOutOfRange { got: n });
        }
        if !strictly_increasing(&self.settlement_epochs) {
            return Err(WireError::EpochsNotStrictlyIncreasing);
        }
        if self.reward_amount_plain.len() != n {
            return Err(WireError::RewardAmountsMisaligned {
                epochs: n,
                amounts: self.reward_amount_plain.len(),
            });
        }
        if self.work_claim.len() != n {
            return Err(WireError::WorkClaimMisaligned {
                epochs: n,
                claims: self.work_claim.len(),
            });
        }
        for (i, claim) in self.work_claim.iter().enumerate() {
            if claim.epoch != self.settlement_epochs[i] {
                return Err(WireError::WorkClaimEpochMismatch {
                    index: i,
                    expected: self.settlement_epochs[i],
                    got: claim.epoch,
                });
            }
            if claim.shard_entries.len() > MAX_HOLDINGS_SHARDS {
                return Err(WireError::ShardEntriesExceeded {
                    got: claim.shard_entries.len(),
                });
            }
        }
        if self.holdings.kind == HoldingsKind::ShardSetCompact
            && self.holdings.shard_ids.len() > MAX_HOLDINGS_SHARDS
        {
            return Err(WireError::Holdings(BondWireError::HoldingsCountExceeded {
                got: self.holdings.shard_ids.len(),
            }));
        }
        if self.holdings.kind == HoldingsKind::CompleteTree && !self.holdings.shard_ids.is_empty() {
            return Err(WireError::Holdings(
                BondWireError::ShardListForbiddenForCompleteTree,
            ));
        }
        let plen = self.backing.proof.len();
        if plen == 0 || plen > MAX_BACKING_PROOF_BYTES {
            return Err(WireError::ProofSizeInvalid { got: plen });
        }
        Ok(())
    }

    /// Canonical work-claim section bytes (also digest field 6 of
    /// [`Self::auth_msg`], so wire and digest cannot drift). Per epoch, in
    /// `settlement_epochs` order: varint entry count, then per entry
    /// `varint shard_id ‖ u8 serve_credit_bit ‖ varint scarcity_milli`.
    /// `WorkEpochClaim::epoch` is intentionally absent (reconstructed from
    /// `settlement_epochs`).
    #[must_use]
    pub fn encode_work_claim(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for claim in &self.work_claim {
            write_varint(&claim.shard_entries.len(), &mut out).expect("vec write");
            for entry in &claim.shard_entries {
                write_varint(&entry.shard_id, &mut out).expect("vec write");
                out.push(u8::from(entry.serve_credit_bit));
                write_varint(&u64::from(entry.scarcity_milli), &mut out).expect("vec write");
            }
        }
        out
    }

    /// Serialize in the frozen §8.0.2 field order:
    /// tag ‖ `P_pubkey` ‖ holdings ‖ epochs ‖ work_claim ‖ backing ‖
    /// per-epoch amounts ‖ `auth_backing` ‖ `auth_claim`.
    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), WireError> {
        self.validate()?;
        w.write_all(&[VIN_TYPE_ARCHIVAL_REWARD_EMISSION])?;
        write_varint(&self.p_pubkey.len(), w)?;
        w.write_all(&self.p_pubkey)?;
        w.write_all(&encode_holdings_descriptor(&self.holdings)?)?;
        write_varint(&self.settlement_epochs.len(), w)?;
        for epoch in &self.settlement_epochs {
            write_varint(epoch, w)?;
        }
        w.write_all(&self.encode_work_claim())?;
        write_varint(&self.backing.proof.len(), w)?;
        w.write_all(&self.backing.proof)?;
        w.write_all(&self.backing.pseudo_out)?;
        w.write_all(&self.backing.pqc_pk_hash)?;
        write_varint(&self.backing.backing_pubkey.len(), w)?;
        w.write_all(&self.backing.backing_pubkey)?;
        w.write_all(&[self.backing.tree_depth])?;
        for amount in &self.reward_amount_plain {
            write_varint(amount, w)?;
        }
        write_varint(&self.auth_backing.len(), w)?;
        w.write_all(&self.auth_backing)?;
        write_varint(&self.auth_claim.len(), w)?;
        w.write_all(&self.auth_claim)?;
        Ok(())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        self.write(&mut out)?;
        Ok(out)
    }

    /// Parse the payload after the type tag. Every count/length is bounds- or
    /// equality-checked **before** its allocation or read.
    pub fn read_payload<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let p_pubkey = read_canonical_pubkey(r, "P_pubkey")?;
        let holdings = read_holdings_descriptor(r)?;
        let epoch_count: usize = read_varint(r)?;
        if epoch_count == 0 || epoch_count > MAX_SETTLEMENT_EPOCHS_PER_EMISSION {
            return Err(WireError::EpochCountOutOfRange { got: epoch_count });
        }
        let mut settlement_epochs = Vec::with_capacity(epoch_count);
        for _ in 0..epoch_count {
            settlement_epochs.push(read_varint(r)?);
        }
        if !strictly_increasing(&settlement_epochs) {
            return Err(WireError::EpochsNotStrictlyIncreasing);
        }
        let mut work_claim = Vec::with_capacity(epoch_count);
        for &epoch in &settlement_epochs {
            let entry_count: usize = read_varint(r)?;
            if entry_count > MAX_HOLDINGS_SHARDS {
                return Err(WireError::ShardEntriesExceeded { got: entry_count });
            }
            let mut shard_entries = Vec::with_capacity(entry_count);
            for _ in 0..entry_count {
                let shard_id = read_varint(r)?;
                let serve_credit_bit = match read_byte(r)? {
                    0 => false,
                    1 => true,
                    other => return Err(WireError::InvalidServeCreditBit(other)),
                };
                let scarcity: u64 = read_varint(r)?;
                let scarcity_milli =
                    u32::try_from(scarcity).map_err(|_| WireError::ScarcityOverflow(scarcity))?;
                shard_entries.push(ShardWorkEntry {
                    shard_id,
                    serve_credit_bit,
                    scarcity_milli,
                });
            }
            work_claim.push(WorkEpochClaim {
                epoch,
                shard_entries,
            });
        }
        let proof_len: usize = read_varint(r)?;
        if proof_len == 0 || proof_len > MAX_BACKING_PROOF_BYTES {
            return Err(WireError::ProofSizeInvalid { got: proof_len });
        }
        let mut proof = vec![0u8; proof_len];
        r.read_exact(&mut proof)?;
        let pseudo_out = read_bytes(r)?;
        let pqc_pk_hash = read_bytes(r)?;
        let backing_pubkey = read_canonical_pubkey(r, "backing_pubkey")?;
        let tree_depth = read_byte(r)?;
        let mut reward_amount_plain = Vec::with_capacity(epoch_count);
        for _ in 0..epoch_count {
            reward_amount_plain.push(read_varint(r)?);
        }
        let auth_backing = read_canonical_sig(r, "auth_backing")?;
        let auth_claim = read_canonical_sig(r, "auth_claim")?;
        Ok(Self {
            p_pubkey,
            holdings,
            settlement_epochs,
            work_claim,
            backing: MembershipOnlyBacking {
                proof,
                pseudo_out,
                pqc_pk_hash,
                backing_pubkey,
                tree_depth,
            },
            reward_amount_plain,
            auth_backing,
            auth_claim,
        })
    }

    /// Length-delimited parse: reject unread trailing bytes.
    pub fn read_payload_exact<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let vin = Self::read_payload(r)?;
        crate::wire::ensure_payload_fully_consumed(r).map_err(|e| match e {
            crate::wire::WireError::TrailingBytes => WireError::TrailingBytes,
            crate::wire::WireError::Io(err) => WireError::Io(err),
            _ => WireError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected wire error during emission parse",
            )),
        })?;
        Ok(vin)
    }

    pub fn read<R: Read>(r: &mut R) -> Result<Self, WireError> {
        let tag = read_byte(r)?;
        if tag != VIN_TYPE_ARCHIVAL_REWARD_EMISSION {
            return Err(WireError::UnknownVinType(tag));
        }
        Self::read_payload(r)
    }

    /// The 64-byte cSHAKE256 binding message both hybrid auths sign — the R1.A
    /// `emission_auth_msg` inventory with the §8.0.3 freeze additions, one field
    /// construction for both roles (wallet builder and PR-E3 verify call this
    /// same function, so signer and verifier cannot drift).
    ///
    /// **Two distinct messages via customization (Q1 ⊕ R1.A).** Q1 ratified
    /// *two* auths over *two distinct* binding messages ("not one signature
    /// checked twice"); R1.A pinned *one* canonical field inventory. Reconciled
    /// here the cSHAKE way: the same length-prefixed field inventory hashed
    /// under role-distinct customizations
    /// ([`EMISSION_AUTH_BACKING_CUSTOMIZATION`] /
    /// [`EMISSION_AUTH_CLAIM_CUSTOMIZATION`]), so a backing signature can never
    /// stand in the claim slot (or vice versa) even under the same key, while
    /// both auths inherit every R1.A anti-replay binding.
    ///
    /// Field inventory (TupleHash-style: each field prefixed with its u64-LE
    /// byte length, in this order):
    /// 1. `P_canonical_id` (§6.1 derivation from `p_pubkey`)
    /// 2. `p_pubkey` canonical bytes (no key substitution)
    /// 3. holdings canonical encoding (§3.4.1 bytes, shared with the bond wire)
    /// 4. `settlement_epochs` (u64-LE each — epoch replay)
    /// 5. `reward_amount_plain` (u64-LE each — §8.0.3: the digest commits the
    ///    vin's loud per-epoch amounts, not just the vout set)
    /// 6. work-claim canonical wire bytes ([`Self::encode_work_claim`])
    /// 7. ordered reward vout commit set (per entry:
    ///    `commitment ‖ amount_plain u64-LE ‖ one_time_key` — destination swap)
    /// 8. `signable_tx_hash` (cross-tx replay)
    ///
    /// `reward_commits` and `signable_tx_hash` are tx-level context supplied by
    /// the caller (wallet builder / PR-E3), not vin fields.
    pub fn auth_msg(
        &self,
        reward_commits: &[RewardCommit],
        signable_tx_hash: &[u8; 32],
        role: EmissionAuthRole,
    ) -> Result<[u8; 64], WireError> {
        let customization = match role {
            EmissionAuthRole::Backing => EMISSION_AUTH_BACKING_CUSTOMIZATION,
            EmissionAuthRole::Claim => EMISSION_AUTH_CLAIM_CUSTOMIZATION,
        };
        fn framed(input: &mut Vec<u8>, bytes: &[u8]) {
            input.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            input.extend_from_slice(bytes);
        }
        let mut input = Vec::new();
        framed(
            &mut input,
            &p_canonical_id_from_hybrid_pubkey(&self.p_pubkey).to_bytes(),
        );
        framed(&mut input, &self.p_pubkey);
        framed(&mut input, &encode_holdings_descriptor(&self.holdings)?);
        let mut epochs = Vec::with_capacity(self.settlement_epochs.len() * 8);
        for epoch in &self.settlement_epochs {
            epochs.extend_from_slice(&epoch.to_le_bytes());
        }
        framed(&mut input, &epochs);
        let mut amounts = Vec::with_capacity(self.reward_amount_plain.len() * 8);
        for amount in &self.reward_amount_plain {
            amounts.extend_from_slice(&amount.to_le_bytes());
        }
        framed(&mut input, &amounts);
        framed(&mut input, &self.encode_work_claim());
        let mut commits = Vec::with_capacity(reward_commits.len() * 72);
        for rc in reward_commits {
            commits.extend_from_slice(&rc.commitment);
            commits.extend_from_slice(&rc.amount_plain.to_le_bytes());
            commits.extend_from_slice(&rc.one_time_key);
        }
        framed(&mut input, &commits);
        framed(&mut input, signable_tx_hash);
        Ok(cshake256_64(customization, &input))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vin() -> ArchivalRewardEmissionVin {
        ArchivalRewardEmissionVin {
            p_pubkey: vec![0xA1; SINGLE_KEY_CANONICAL_LEN],
            holdings: HoldingsDescriptor {
                kind: HoldingsKind::ShardSetCompact,
                shard_ids: vec![7, 42],
            },
            settlement_epochs: vec![11, 12, 15],
            work_claim: vec![
                WorkEpochClaim {
                    epoch: 11,
                    shard_entries: vec![
                        ShardWorkEntry {
                            shard_id: 7,
                            serve_credit_bit: true,
                            scarcity_milli: 850,
                        },
                        ShardWorkEntry {
                            shard_id: 42,
                            serve_credit_bit: false,
                            scarcity_milli: 0,
                        },
                    ],
                },
                WorkEpochClaim {
                    epoch: 12,
                    shard_entries: vec![ShardWorkEntry {
                        shard_id: 7,
                        serve_credit_bit: true,
                        scarcity_milli: 1_000,
                    }],
                },
                WorkEpochClaim {
                    epoch: 15,
                    shard_entries: vec![],
                },
            ],
            backing: MembershipOnlyBacking {
                proof: vec![0xEE; 4096],
                pseudo_out: [0x22; 32],
                pqc_pk_hash: [0x33; 32],
                backing_pubkey: vec![0xB2; SINGLE_KEY_CANONICAL_LEN],
                tree_depth: 3,
            },
            reward_amount_plain: vec![1_000_000, 2_000_000, 0],
            auth_backing: vec![0xC3; SINGLE_SIG_CANONICAL_LEN],
            auth_claim: vec![0xD4; SINGLE_SIG_CANONICAL_LEN],
        }
    }

    fn sample_commits() -> Vec<RewardCommit> {
        vec![RewardCommit {
            commitment: [0x55; 32],
            amount_plain: 3_000_000,
            one_time_key: [0x66; 32],
        }]
    }

    #[test]
    fn emission_roundtrip_shard_set_and_complete_tree() {
        let vin = sample_vin();
        let wire = vin.serialize().unwrap();
        assert_eq!(wire[0], VIN_TYPE_ARCHIVAL_REWARD_EMISSION);
        let decoded = ArchivalRewardEmissionVin::read(&mut wire.as_slice()).unwrap();
        assert_eq!(decoded, vin);

        let mut ct = sample_vin();
        ct.holdings = HoldingsDescriptor {
            kind: HoldingsKind::CompleteTree,
            shard_ids: Vec::new(),
        };
        let wire = ct.serialize().unwrap();
        let decoded = ArchivalRewardEmissionVin::read(&mut wire.as_slice()).unwrap();
        assert_eq!(decoded, ct);
    }

    #[test]
    fn emission_rejects_wrong_tag_and_trailing_bytes() {
        let vin = sample_vin();
        let mut wire = vin.serialize().unwrap();
        wire[0] = 0x03; // bond-post tag
        assert!(matches!(
            ArchivalRewardEmissionVin::read(&mut wire.as_slice()),
            Err(WireError::UnknownVinType(0x03))
        ));

        let mut wire = vin.serialize().unwrap();
        wire.push(0x00);
        let mut r = &wire[1..]; // skip tag; exact-parse the payload
        assert!(matches!(
            ArchivalRewardEmissionVin::read_payload_exact(&mut r),
            Err(WireError::TrailingBytes)
        ));
    }

    #[test]
    fn emission_rejects_structural_violations() {
        // Non-canonical key/sig lengths.
        let mut vin = sample_vin();
        vin.p_pubkey.push(0);
        assert!(matches!(
            vin.serialize(),
            Err(WireError::PubkeyLenNotCanonical {
                field: "P_pubkey",
                ..
            })
        ));
        let mut vin = sample_vin();
        vin.backing.backing_pubkey.pop();
        assert!(matches!(
            vin.serialize(),
            Err(WireError::PubkeyLenNotCanonical {
                field: "backing_pubkey",
                ..
            })
        ));
        let mut vin = sample_vin();
        vin.auth_claim.pop();
        assert!(matches!(
            vin.serialize(),
            Err(WireError::SigLenNotCanonical {
                field: "auth_claim",
                ..
            })
        ));

        // Epoch set: empty, oversized, non-increasing (write side).
        let mut vin = sample_vin();
        vin.settlement_epochs.clear();
        vin.work_claim.clear();
        vin.reward_amount_plain.clear();
        assert!(matches!(
            vin.serialize(),
            Err(WireError::EpochCountOutOfRange { got: 0 })
        ));
        let mut vin = sample_vin();
        vin.settlement_epochs = vec![11, 11, 15];
        assert!(matches!(
            vin.serialize(),
            Err(WireError::EpochsNotStrictlyIncreasing)
        ));

        // Alignment (only representable in the struct; the wire derives counts).
        let mut vin = sample_vin();
        vin.reward_amount_plain.pop();
        assert!(matches!(
            vin.serialize(),
            Err(WireError::RewardAmountsMisaligned { .. })
        ));
        let mut vin = sample_vin();
        vin.work_claim[1].epoch = 13;
        assert!(matches!(
            vin.serialize(),
            Err(WireError::WorkClaimEpochMismatch { index: 1, .. })
        ));

        // Backing proof bounds.
        let mut vin = sample_vin();
        vin.backing.proof.clear();
        assert!(matches!(
            vin.serialize(),
            Err(WireError::ProofSizeInvalid { got: 0 })
        ));
        let mut vin = sample_vin();
        vin.backing.proof = vec![0; MAX_BACKING_PROOF_BYTES + 1];
        assert!(matches!(
            vin.serialize(),
            Err(WireError::ProofSizeInvalid { .. })
        ));
    }

    #[test]
    fn emission_read_rejects_hostile_counts_before_allocation() {
        // Payload with a huge epoch count: canonical pubkey, CompleteTree
        // holdings, then a varint epoch count of 2^30 — must reject at the
        // count check, never allocating.
        let mut wire = Vec::new();
        write_varint(&SINGLE_KEY_CANONICAL_LEN, &mut wire).unwrap();
        wire.extend_from_slice(&vec![0xA1; SINGLE_KEY_CANONICAL_LEN]);
        wire.push(HoldingsKind::CompleteTree as u8);
        write_varint(&(1usize << 30), &mut wire).unwrap();
        assert!(matches!(
            ArchivalRewardEmissionVin::read_payload(&mut wire.as_slice()),
            Err(WireError::EpochCountOutOfRange { .. })
        ));

        // Bad serve-credit bit on the wire.
        let vin = sample_vin();
        let wire = vin.serialize().unwrap();
        // Find the first serve_credit byte: rebuild the prefix up to it.
        let mut prefix = Vec::new();
        write_varint(&SINGLE_KEY_CANONICAL_LEN, &mut prefix).unwrap();
        prefix.extend_from_slice(&vin.p_pubkey);
        prefix.extend_from_slice(&encode_holdings_descriptor(&vin.holdings).unwrap());
        write_varint(&vin.settlement_epochs.len(), &mut prefix).unwrap();
        for e in &vin.settlement_epochs {
            write_varint(e, &mut prefix).unwrap();
        }
        write_varint(&vin.work_claim[0].shard_entries.len(), &mut prefix).unwrap();
        write_varint(&vin.work_claim[0].shard_entries[0].shard_id, &mut prefix).unwrap();
        let bit_pos = 1 + prefix.len(); // +1 for the tag byte in `wire`
        let mut tampered = wire.clone();
        tampered[bit_pos] = 2;
        assert!(matches!(
            ArchivalRewardEmissionVin::read(&mut tampered.as_slice()),
            Err(WireError::InvalidServeCreditBit(2))
        ));
    }

    #[test]
    fn auth_msg_is_stable_role_separated_and_non_replayable() {
        let vin = sample_vin();
        let commits = sample_commits();
        let txh = [0x42u8; 32];

        let backing_1 = vin
            .auth_msg(&commits, &txh, EmissionAuthRole::Backing)
            .unwrap();
        let backing_2 = vin
            .auth_msg(&commits, &txh, EmissionAuthRole::Backing)
            .unwrap();
        let claim = vin
            .auth_msg(&commits, &txh, EmissionAuthRole::Claim)
            .unwrap();
        assert_eq!(backing_1, backing_2, "digest must be deterministic");
        assert_ne!(
            backing_1, claim,
            "Q1: the two auth roles must sign distinct messages"
        );

        // Each anti-replay binding flips the digest.
        let mut v = sample_vin();
        v.settlement_epochs[2] = 16;
        v.work_claim[2].epoch = 16;
        assert_ne!(
            v.auth_msg(&commits, &txh, EmissionAuthRole::Claim).unwrap(),
            claim,
            "epoch set must be bound"
        );
        let mut v = sample_vin();
        v.reward_amount_plain[0] += 1;
        assert_ne!(
            v.auth_msg(&commits, &txh, EmissionAuthRole::Claim).unwrap(),
            claim,
            "per-epoch amounts must be bound (§8.0.3)"
        );
        let mut swapped = sample_commits();
        swapped[0].one_time_key = [0x77; 32];
        assert_ne!(
            vin.auth_msg(&swapped, &txh, EmissionAuthRole::Claim)
                .unwrap(),
            claim,
            "reward destination must be bound (mint-destination swap)"
        );
        let other_txh = [0x43u8; 32];
        assert_ne!(
            vin.auth_msg(&commits, &other_txh, EmissionAuthRole::Claim)
                .unwrap(),
            claim,
            "signable_tx_hash must be bound (cross-tx replay)"
        );
    }
}
