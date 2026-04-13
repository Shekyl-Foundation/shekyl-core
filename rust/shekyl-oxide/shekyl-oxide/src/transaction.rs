use core::cmp::Ordering;
#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::io::{self, Read, Write};

use zeroize::Zeroize;

use crate::{
  io::*,
  primitives::keccak256,
  fcmp::{bulletproofs::Bulletproof, PrunedProofs},
};

/// The maximum size for a non-miner transaction.
pub const MAX_NON_MINER_TRANSACTION_SIZE: usize = 1_000_000;

const MAX_MINER_TRANSACTION_INPUTS: usize = 1;

const NON_MINER_TRANSACTION_INPUT_SIZE_LOWER_BOUND: usize = 32;
const NON_MINER_TRANSACTION_INPUTS_UPPER_BOUND: usize =
  MAX_NON_MINER_TRANSACTION_SIZE / NON_MINER_TRANSACTION_INPUT_SIZE_LOWER_BOUND;

const fn const_max(a: usize, b: usize) -> usize {
  if a > b {
    a
  } else {
    b
  }
}

/// An upper bound for the amount of inputs within a transaction.
pub const INPUTS_UPPER_BOUND: usize =
  const_max(MAX_MINER_TRANSACTION_INPUTS, NON_MINER_TRANSACTION_INPUTS_UPPER_BOUND);

const NON_MINER_TRANSACTION_OUTPUT_SIZE_LOWER_BOUND: usize = 32;
const MAX_NON_MINER_TRANSACTION_OUTPUTS: usize =
  MAX_NON_MINER_TRANSACTION_SIZE / NON_MINER_TRANSACTION_OUTPUT_SIZE_LOWER_BOUND;

/// An input in the Shekyl protocol.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Input {
  /// An input for a miner transaction, which is generating new coins.
  Gen(usize),
  /// An input spending an output on-chain.
  ToKey {
    /// The pool this input spends an output of.
    amount: Option<u64>,
    /// Offset list (empty for FCMP++, which proves against the full UTXO set).
    key_offsets: Vec<u64>,
    /// The key image (linking tag, nullifier) for the spent output.
    key_image: CompressedPoint,
  },
  /// A stake reward claim input (tag 0x03 in binary serialization).
  StakeClaim {
    /// Claimed reward amount.
    amount: u64,
    /// Global output index of the staked output being claimed against.
    staked_output_index: u64,
    /// Claim range start (exclusive: last_claimed_height or creation height).
    from_height: u64,
    /// Claim range end (inclusive); capped at min(current_height, lock_until).
    to_height: u64,
    /// Prevents double-claim for this range.
    key_image: CompressedPoint,
  },
}

impl Input {
  /// Write the Input.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      Input::Gen(height) => {
        w.write_all(&[255])?;
        write_varint(height, w)
      }
      Input::ToKey { amount, key_offsets, key_image } => {
        w.write_all(&[2])?;
        write_varint(&amount.unwrap_or(0), w)?;
        write_vec(write_varint, key_offsets, w)?;
        key_image.write(w)
      }
      Input::StakeClaim { amount, staked_output_index, from_height, to_height, key_image } => {
        w.write_all(&[3])?;
        write_varint(amount, w)?;
        write_varint(staked_output_index, w)?;
        write_varint(from_height, w)?;
        write_varint(to_height, w)?;
        key_image.write(w)
      }
    }
  }

  /// Serialize the Input to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = vec![];
    self.write(&mut res).expect("write failed but <Vec as io::Write> doesn't fail");
    res
  }

  /// Read an Input.
  pub fn read<R: Read>(r: &mut R) -> io::Result<Input> {
    Ok(match read_byte(r)? {
      255 => Input::Gen(read_varint(r)?),
      2 => {
        let amount = read_varint(r)?;
        let amount = if amount == 0 { None } else { Some(amount) };
        Input::ToKey {
          amount,
          key_offsets: read_vec(read_varint, Some(MAX_NON_MINER_TRANSACTION_SIZE), r)?,
          key_image: CompressedPoint::read(r)?,
        }
      }
      3 => Input::StakeClaim {
        amount: read_varint(r)?,
        staked_output_index: read_varint(r)?,
        from_height: read_varint(r)?,
        to_height: read_varint(r)?,
        key_image: CompressedPoint::read(r)?,
      },
      _ => Err(io::Error::other("Tried to deserialize unknown/unused input type"))?,
    })
  }
}

/// An output in the Shekyl protocol.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Output {
  /// The pool this output should be sorted into.
  pub amount: Option<u64>,
  /// The key which can spend this output.
  pub key: CompressedPoint,
  /// The view tag for this output, as used to accelerate scanning.
  pub view_tag: Option<u8>,
  /// If this output is a staked output, the staking metadata.
  pub staking: Option<StakingMeta>,
}

/// Metadata attached to a staked output (serialized as tag 0x04).
///
/// `lock_until` is not stored on-chain. The effective lock expiry is computed
/// dynamically as `creation_height + tier_lock_blocks` wherever needed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct StakingMeta {
  /// Tier index: 0=short, 1=medium, 2=long.
  pub lock_tier: u8,
}

impl Output {
  /// Write the Output.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    write_varint(&self.amount.unwrap_or(0), w)?;
    if let Some(staking) = &self.staking {
      w.write_all(&[4])?; // txout_to_staked_key tag
      w.write_all(&self.key.to_bytes())?;
      if let Some(view_tag) = self.view_tag {
        w.write_all(&[view_tag])?;
      } else {
        w.write_all(&[0])?;
      }
      w.write_all(&[staking.lock_tier])?;
    } else {
      w.write_all(&[2 + u8::from(self.view_tag.is_some())])?;
      w.write_all(&self.key.to_bytes())?;
      if let Some(view_tag) = self.view_tag {
        w.write_all(&[view_tag])?;
      }
    }
    Ok(())
  }

  /// Write the Output to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(8 + 1 + 32);
    self.write(&mut res).expect("write failed but <Vec as io::Write> doesn't fail");
    res
  }

  /// Read an Output.
  pub fn read<R: Read>(rct: bool, r: &mut R) -> io::Result<Output> {
    let raw_amount: u64 = read_varint(r)?;

    let tag = read_byte(r)?;
    match tag {
      2 | 3 => {
        let amount = if rct {
          if raw_amount != 0 {
            Err(io::Error::other("confidential TX output amount wasn't 0"))?;
          }
          None
        } else {
          Some(raw_amount)
        };
        let key = CompressedPoint::read(r)?;
        let view_tag = if tag == 3 { Some(read_byte(r)?) } else { None };
        Ok(Output { amount, key, view_tag, staking: None })
      }
      4 => {
        // txout_to_staked_key: key(32) view_tag(1) lock_tier(1)
        // Staked outputs have explicit (non-zero) amounts regardless of RCT flag
        let amount = Some(raw_amount);
        let key = CompressedPoint::read(r)?;
        let view_tag = Some(read_byte(r)?);
        let lock_tier = read_byte(r)?;
        Ok(Output {
          amount,
          key,
          view_tag,
          staking: Some(StakingMeta { lock_tier }),
        })
      }
      _ => Err(io::Error::other("Tried to deserialize unknown/unused output type")),
    }
  }
}

/// An additional timelock for a transaction.
///
/// Outputs are locked by a default timelock. If a timelock is explicitly specified, the
/// longer of the two will be the timelock used.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum Timelock {
  /// No additional timelock.
  None,
  /// Additionally locked until this block.
  Block(usize),
  /// Additionally locked until this many seconds since the epoch.
  Time(u64),
}

impl Timelock {
  /// Write the Timelock.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    match self {
      Timelock::None => write_varint(&0u8, w),
      Timelock::Block(block) => write_varint(block, w),
      Timelock::Time(time) => write_varint(time, w),
    }
  }

  /// Serialize the Timelock to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(1);
    self.write(&mut res).expect("write failed but <Vec as io::Write> doesn't fail");
    res
  }

  /// Read a Timelock.
  pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
    const TIMELOCK_BLOCK_THRESHOLD: usize = 500_000_000;

    let raw = read_varint::<_, u64>(r)?;
    Ok(if raw == 0 {
      Timelock::None
    } else if raw <
      u64::try_from(TIMELOCK_BLOCK_THRESHOLD)
        .expect("TIMELOCK_BLOCK_THRESHOLD didn't fit in a u64")
    {
      Timelock::Block(usize::try_from(raw).expect(
        "timelock overflowed usize despite being less than a const representable with a usize",
      ))
    } else {
      Timelock::Time(raw)
    })
  }
}

impl PartialOrd for Timelock {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    match (self, other) {
      (Timelock::None, Timelock::None) => Some(Ordering::Equal),
      (Timelock::None, _) => Some(Ordering::Less),
      (_, Timelock::None) => Some(Ordering::Greater),
      (Timelock::Block(a), Timelock::Block(b)) => a.partial_cmp(b),
      (Timelock::Time(a), Timelock::Time(b)) => a.partial_cmp(b),
      _ => None,
    }
  }
}

/// The transaction prefix.
///
/// Contains most parts of the transaction needed to handle it. Excludes proofs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransactionPrefix {
  /// The timelock this transaction is additionally constrained by.
  pub additional_timelock: Timelock,
  /// The inputs for this transaction.
  pub inputs: Vec<Input>,
  /// The outputs for this transaction.
  pub outputs: Vec<Output>,
  /// The additional data included within the transaction (used by wallets for scanning data).
  pub extra: Vec<u8>,
}

impl TransactionPrefix {
  fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    self.additional_timelock.write(w)?;
    write_vec(Input::write, &self.inputs, w)?;
    write_vec(Output::write, &self.outputs, w)?;
    write_varint(&self.extra.len(), w)?;
    w.write_all(&self.extra)
  }

  /// Read a TransactionPrefix.
  pub fn read<R: Read>(r: &mut R) -> io::Result<TransactionPrefix> {
    let additional_timelock = Timelock::read(r)?;

    let inputs = read_vec(|r| Input::read(r), Some(INPUTS_UPPER_BOUND), r)?;
    if inputs.is_empty() {
      Err(io::Error::other("transaction had no inputs"))?;
    }
    let is_miner_tx = matches!(inputs[0], Input::Gen { .. });

    let max_outputs = if is_miner_tx { None } else { Some(MAX_NON_MINER_TRANSACTION_OUTPUTS) };
    let mut prefix = TransactionPrefix {
      additional_timelock,
      inputs,
      outputs: read_vec(|r| Output::read(!is_miner_tx, r), max_outputs, r)?,
      extra: vec![],
    };
    let max_extra = if is_miner_tx { None } else { Some(MAX_NON_MINER_TRANSACTION_SIZE) };
    prefix.extra = read_vec(read_byte, max_extra, r)?;
    Ok(prefix)
  }

  fn hash(&self) -> [u8; 32] {
    let mut buf = vec![];
    write_varint(&2u8, &mut buf).expect("write failed but <Vec as io::Write> doesn't fail");
    self.write(&mut buf).expect("write failed but <Vec as io::Write> doesn't fail");
    keccak256(buf)
  }
}

#[allow(private_bounds, private_interfaces)]
mod sealed {
  use core::fmt::Debug;
  use crate::fcmp::*;
  use super::*;

  pub(crate) trait PotentiallyPrunedProofs: Clone + PartialEq + Eq + Debug {
    fn write(&self, w: &mut impl Write) -> io::Result<()>;
    fn read(inputs: usize, outputs: usize, r: &mut impl Read) -> io::Result<Option<Self>>;
  }

  impl PotentiallyPrunedProofs for Proofs {
    fn write(&self, w: &mut impl Write) -> io::Result<()> {
      self.write(w)
    }
    fn read(inputs: usize, outputs: usize, r: &mut impl Read) -> io::Result<Option<Self>> {
      Proofs::read(inputs, outputs, r)
    }
  }

  impl PotentiallyPrunedProofs for PrunedProofs {
    fn write(&self, w: &mut impl Write) -> io::Result<()> {
      self.base.write(w, crate::fcmp::ProofType::FcmpPlusPlusPqc)
    }
    fn read(_inputs: usize, outputs: usize, r: &mut impl Read) -> io::Result<Option<Self>> {
      Ok(ProofBase::read(outputs, r)?.map(|(_proof_type, base)| Self { base }))
    }
  }

  trait Sealed {}

  /// A trait representing either pruned or not pruned proofs.
  pub trait PotentiallyPruned: Sealed {
    /// Potentially-pruned proofs.
    type Proofs: PotentiallyPrunedProofs;
  }
  /// A marker for an object which isn't pruned.
  #[derive(Clone, PartialEq, Eq, Debug)]
  pub struct NotPruned;
  impl Sealed for NotPruned {}
  impl PotentiallyPruned for NotPruned {
    type Proofs = Proofs;
  }
  /// A marker for an object which is pruned.
  #[derive(Clone, PartialEq, Eq, Debug)]
  pub struct Pruned;
  impl Sealed for Pruned {}
  impl PotentiallyPruned for Pruned {
    type Proofs = PrunedProofs;
  }
}
pub use sealed::*;

/// A Shekyl transaction (always version 2).
///
/// Shekyl does not support v1 (CryptoNote) transactions. All transactions use v2
/// with FCMP++ proofs.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Transaction<P: PotentiallyPruned = NotPruned> {
  /// A version 2 transaction with FCMP++ proofs (or coinbase with no proofs).
  V2 {
    /// The transaction's prefix.
    prefix: TransactionPrefix,
    /// The transaction's proofs (None for coinbase).
    proofs: Option<P::Proofs>,
  },
}

#[allow(private_bounds)]
impl<P: PotentiallyPruned> Transaction<P> {
  /// Get the version of this transaction (always 2).
  pub fn version(&self) -> u8 {
    2
  }

  /// Get the TransactionPrefix of this transaction.
  pub fn prefix(&self) -> &TransactionPrefix {
    match self {
      Transaction::V2 { prefix, .. } => prefix,
    }
  }

  /// Get a mutable reference to the TransactionPrefix of this transaction.
  pub fn prefix_mut(&mut self) -> &mut TransactionPrefix {
    match self {
      Transaction::V2 { prefix, .. } => prefix,
    }
  }

  /// Write the Transaction.
  pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
    write_varint(&2u8, w)?;
    let Transaction::V2 { prefix, proofs } = self;
    prefix.write(w)?;
    match proofs {
      None => w.write_all(&[0])?,
      Some(proofs) => proofs.write(w)?,
    }
    Ok(())
  }

  /// Write the Transaction to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(2048);
    self.write(&mut res).expect("write failed but <Vec as io::Write> doesn't fail");
    res
  }

  /// Read a Transaction.
  pub fn read<R: Read>(r: &mut R) -> io::Result<Self> {
    let version: u64 = read_varint(r)?;
    if version != 2 {
      Err(io::Error::other("only v2 transactions are supported by Shekyl"))?;
    }
    let prefix = TransactionPrefix::read(r)?;

    let proofs = P::Proofs::read(prefix.inputs.len(), prefix.outputs.len(), r)?;
    Ok(Transaction::V2 { prefix, proofs })
  }
}

impl Transaction<NotPruned> {
  /// The hash of the transaction.
  pub fn hash(&self) -> [u8; 32] {
    let Transaction::V2 { prefix, proofs } = self;
    let mut hashes = Vec::with_capacity(96);

    hashes.extend(prefix.hash());

    if let Some(proofs) = proofs {
      let mut buf = Vec::with_capacity(512);
      proofs
        .base
        .write(&mut buf, proofs.proof_type())
        .expect("write failed but <Vec as io::Write> doesn't fail");
      hashes.extend(keccak256(&buf));

      let mut prunable_buf = Vec::with_capacity(1024);
      proofs
        .prunable
        .write(&mut prunable_buf)
        .expect("write failed but <Vec as io::Write> doesn't fail");
      hashes.extend(keccak256(prunable_buf));
    } else {
      hashes.extend(keccak256([0]));
      hashes.extend([0; 32]);
    }

    keccak256(hashes)
  }

  /// Calculate the hash of this transaction as needed for signing it.
  ///
  /// Returns None if the transaction is a coinbase (without proofs).
  pub fn signature_hash(&self) -> Option<[u8; 32]> {
    let Transaction::V2 { prefix, proofs } = self;
    let proofs = proofs.as_ref()?;

    let mut hashes = Vec::with_capacity(96);
    hashes.extend(prefix.hash());

    let mut base_buf = Vec::with_capacity(512);
    proofs
      .base
      .write(&mut base_buf, proofs.proof_type())
      .expect("write failed but <Vec as io::Write> doesn't fail");
    hashes.extend(keccak256(&base_buf));

    let mut sig_buf = Vec::with_capacity(1024);
    proofs
      .prunable
      .signature_write(&mut sig_buf)
      .expect("write failed but <Vec as io::Write> doesn't fail");
    hashes.extend(keccak256(sig_buf));

    Some(keccak256(hashes))
  }

  /// Calculate the transaction's weight.
  pub fn weight(&self) -> usize {
    let blob_size = self.serialize().len();
    let Transaction::V2 { prefix, proofs } = self;
    if proofs.is_none() {
      return blob_size;
    }
    blob_size + Bulletproof::calculate_clawback(true, prefix.outputs.len()).0
  }
}

impl From<Transaction<NotPruned>> for Transaction<Pruned> {
  fn from(tx: Transaction<NotPruned>) -> Transaction<Pruned> {
    let Transaction::V2 { prefix, proofs } = tx;
    Transaction::V2 {
      prefix,
      proofs: proofs.map(|proofs| PrunedProofs { base: proofs.base }),
    }
  }
}
