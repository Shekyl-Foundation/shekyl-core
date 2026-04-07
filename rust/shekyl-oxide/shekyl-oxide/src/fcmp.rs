#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::io::{self, Read, Write};

use zeroize::Zeroize;

pub use shekyl_bulletproofs as bulletproofs;
pub use shekyl_fcmp_plus_plus as fcmp_pp;

use crate::{io::*, fcmp::bulletproofs::Bulletproof};

/// Upper bound on serialized FCMP++ proof size (bounded by max transaction size).
const MAX_FCMP_PROOF_SIZE: usize = 1_000_000;

/// Upper bound on a single PQC auth signature blob (ML-DSA-65 signatures are ~3309 bytes).
const MAX_PQC_AUTH_SIZE: usize = 4096;

/// An encrypted amount (compact form, 8 bytes).
///
/// Shekyl only uses the compact encrypted amount format introduced with Bulletproof+.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EncryptedAmount {
  /// The amount, as a u64, encrypted.
  pub amount: [u8; 8],
}

impl EncryptedAmount {
  /// Read an EncryptedAmount from a reader.
  pub fn read<R: Read>(r: &mut R) -> io::Result<EncryptedAmount> {
    Ok(EncryptedAmount { amount: read_bytes(r)? })
  }

  /// Write the EncryptedAmount to a writer.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(&self.amount)
  }
}

/// The proof type used by a transaction.
///
/// Shekyl only accepts `FcmpPlusPlusPqc` from genesis. Legacy Monero types (MLSAG, Borromean,
/// CLSAG, Bulletproof-only) have been removed. Wire values 1-6 are permanently rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum ProofType {
  /// FCMP++ membership proof with per-output PQC keys and Bulletproof+ range proofs.
  ///
  /// Wire value 7. The only ProofType accepted by Shekyl consensus.
  FcmpPlusPlusPqc,
}

impl From<ProofType> for u8 {
  fn from(proof_type: ProofType) -> u8 {
    match proof_type {
      ProofType::FcmpPlusPlusPqc => 7,
    }
  }
}

impl TryFrom<u8> for ProofType {
  type Error = ();
  fn try_from(byte: u8) -> Result<Self, ()> {
    match byte {
      7 => Ok(ProofType::FcmpPlusPlusPqc),
      _ => Err(()),
    }
  }
}

/// The base transaction proof data.
///
/// Contains data needed to handle the transaction and scan it. Excludes proofs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProofBase {
  /// The fee used by this transaction.
  pub fee: u64,
  /// The encrypted amounts for the recipients to decrypt.
  pub encrypted_amounts: Vec<EncryptedAmount>,
  /// The output commitments.
  pub commitments: Vec<CompressedPoint>,
}

impl ProofBase {
  /// Write the ProofBase.
  pub fn write<W: Write>(&self, w: &mut W, proof_type: ProofType) -> io::Result<()> {
    w.write_all(&[u8::from(proof_type)])?;
    write_varint(&self.fee, w)?;
    for encrypted_amount in &self.encrypted_amounts {
      encrypted_amount.write(w)?;
    }
    write_raw_vec(CompressedPoint::write, &self.commitments, w)
  }

  /// Read a ProofBase.
  pub fn read<R: Read>(
    outputs: usize,
    r: &mut R,
  ) -> io::Result<Option<(ProofType, ProofBase)>> {
    let proof_type = read_byte(r)?;
    if proof_type == 0 {
      return Ok(None);
    }
    let proof_type =
      ProofType::try_from(proof_type).map_err(|()| io::Error::other("invalid proof type"))?;

    if outputs == 0 {
      Err(io::Error::other("FCMP++ transaction had 0 outputs"))?;
    }

    Ok(Some((
      proof_type,
      ProofBase {
        fee: read_varint(r)?,
        encrypted_amounts: (0 .. outputs)
          .map(|_| EncryptedAmount::read(r))
          .collect::<Result<_, _>>()?,
        commitments: read_raw_vec(CompressedPoint::read, outputs, r)?,
      },
    )))
  }
}

/// The prunable transaction proof data.
///
/// Contains the FCMP++ proof, BP+ range proof, and PQC authentication signatures.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrunableProof {
  /// The re-blinded commitments for the outputs being spent.
  pub pseudo_outs: Vec<CompressedPoint>,
  /// The aggregate Bulletproof+, proving the outputs are within range.
  pub bulletproof: Bulletproof,
  /// The curve tree snapshot height this proof is relative to.
  pub reference_block: u64,
  /// The serialized FCMP++ proof (membership + SAL proofs).
  ///
  /// Stored as opaque bytes at the protocol layer. Higher layers should deserialize using
  /// the `fcmp_pp` crate, which requires the tree layer count as context.
  pub fcmp_proof: Vec<u8>,
  /// Per-input PQC authentication signatures (ML-DSA-65).
  ///
  /// Each entry is an opaque signature blob for one input.
  pub pqc_auths: Vec<Vec<u8>>,
}

impl PrunableProof {
  /// Write the PrunableProof.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    w.write_all(&[1])?;
    self.bulletproof.write(w)?;

    write_varint(&self.reference_block, w)?;
    write_varint(&self.fcmp_proof.len(), w)?;
    w.write_all(&self.fcmp_proof)?;

    write_varint(&self.pqc_auths.len(), w)?;
    for auth in &self.pqc_auths {
      write_varint(&auth.len(), w)?;
      w.write_all(auth)?;
    }

    write_raw_vec(CompressedPoint::write, &self.pseudo_outs, w)
  }

  /// Serialize the PrunableProof to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = vec![];
    self
      .write(&mut serialized)
      .expect("write failed but <Vec as io::Write> doesn't fail");
    serialized
  }

  /// Read a PrunableProof.
  pub fn read<R: Read>(inputs: usize, r: &mut R) -> io::Result<PrunableProof> {
    if read_varint::<_, u64>(r)? != 1 {
      Err(io::Error::other("n bulletproofs instead of one"))?;
    }
    let bulletproof = Bulletproof::read_plus(r)?;

    let reference_block: u64 = read_varint(r)?;

    let fcmp_proof_len: usize = read_varint(r)?;
    if fcmp_proof_len > MAX_FCMP_PROOF_SIZE {
      Err(io::Error::other("FCMP++ proof exceeds maximum allowed size"))?;
    }
    let fcmp_proof = read_raw_vec(read_byte, fcmp_proof_len, r)?;

    let n_pqc_auths: usize = read_varint(r)?;
    if n_pqc_auths != inputs {
      Err(io::Error::other("pqc_auths count does not match input count"))?;
    }
    let mut pqc_auths = Vec::with_capacity(n_pqc_auths);
    for _ in 0 .. n_pqc_auths {
      let auth_len: usize = read_varint(r)?;
      if auth_len > MAX_PQC_AUTH_SIZE {
        Err(io::Error::other("PQC auth signature exceeds maximum allowed size"))?;
      }
      pqc_auths.push(read_raw_vec(read_byte, auth_len, r)?);
    }

    let pseudo_outs = read_raw_vec(CompressedPoint::read, inputs, r)?;

    Ok(PrunableProof { pseudo_outs, bulletproof, reference_block, fcmp_proof, pqc_auths })
  }

  /// Write the PrunableProof as necessary for signing the signature.
  pub(crate) fn signature_write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.bulletproof.signature_write(w)?;
    w.write_all(&self.fcmp_proof)?;
    for auth in &self.pqc_auths {
      w.write_all(auth)?;
    }
    Ok(())
  }
}

/// The transaction proofs.
///
/// Contains both the ProofBase and PrunableProof structs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Proofs {
  /// The data necessary for handling this transaction.
  pub base: ProofBase,
  /// The data necessary for verifying this transaction.
  pub prunable: PrunableProof,
}

impl Proofs {
  /// The ProofType for this Proofs struct (always FcmpPlusPlusPqc).
  pub fn proof_type(&self) -> ProofType {
    ProofType::FcmpPlusPlusPqc
  }

  /// Write the Proofs.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    let proof_type = self.proof_type();
    self.base.write(w, proof_type)?;
    self.prunable.write(w)
  }

  /// Serialize the Proofs to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = vec![];
    self.write(&mut serialized).expect("write failed but <Vec as io::Write> doesn't fail");
    serialized
  }

  /// Read a Proofs.
  pub fn read<R: Read>(inputs: usize, outputs: usize, r: &mut R) -> io::Result<Option<Proofs>> {
    let Some((_proof_type, base)) = ProofBase::read(outputs, r)? else { return Ok(None) };
    Ok(Some(Proofs { base, prunable: PrunableProof::read(inputs, r)? }))
  }
}

/// A pruned set of proofs (base data only, no prunable proof data).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrunedProofs {
  /// The data necessary for handling this transaction.
  pub base: ProofBase,
}
