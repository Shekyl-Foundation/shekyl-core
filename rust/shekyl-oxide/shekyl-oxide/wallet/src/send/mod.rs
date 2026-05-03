use core::fmt;
use std_shims::{
  io,
  vec::Vec,
  string::{String, ToString},
};

use zeroize::{Zeroize, Zeroizing};

use rand_core::{RngCore, CryptoRng};
use rand::seq::SliceRandom;

use curve25519_dalek::Scalar;
#[cfg(feature = "multisig")]
use frost::FrostError;

use crate::{
  io::*,
  generators::MAX_BULLETPROOF_COMMITMENTS,
  fcmp::ProofType,
  transaction::{INPUTS_UPPER_BOUND, Transaction},
  address::{Network, SubaddressIndex, ShekylAddress},
  extra::{MAX_ARBITRARY_DATA_SIZE, MAX_EXTRA_SIZE_BY_RELAY_RULE},
  rpc::FeeRate,
  ViewPair, GuaranteedViewPair, OutputWithDecoys,
};

mod tx_keys;
pub use tx_keys::TransactionKeys;
mod tx;
mod eventuality;
pub use eventuality::Eventuality;

#[cfg(feature = "multisig")]
mod multisig;
#[cfg(feature = "multisig")]
pub use multisig::{TransactionMachine, TransactionSignMachine, TransactionSignatureMachine};

pub(crate) fn key_image_sort(x: &CompressedPoint, y: &CompressedPoint) -> core::cmp::Ordering {
  x.cmp(y).reverse()
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
enum ChangeEnum {
  AddressOnly(ShekylAddress),
  Standard { view_pair: ViewPair, subaddress: Option<SubaddressIndex> },
  Guaranteed { view_pair: GuaranteedViewPair, subaddress: Option<SubaddressIndex> },
}

impl fmt::Debug for ChangeEnum {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      ChangeEnum::AddressOnly(addr) => {
        f.debug_struct("ChangeEnum::AddressOnly").field("addr", &addr).finish()
      }
      ChangeEnum::Standard { subaddress, .. } => f
        .debug_struct("ChangeEnum::Standard")
        .field("subaddress", &subaddress)
        .finish_non_exhaustive(),
      ChangeEnum::Guaranteed { subaddress, .. } => f
        .debug_struct("ChangeEnum::Guaranteed")
        .field("subaddress", &subaddress)
        .finish_non_exhaustive(),
    }
  }
}

/// Specification for a change output.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Change(Option<ChangeEnum>);

impl Change {
  /// Create a change output specification.
  ///
  /// This take the view key as Monero assumes it has the view key for change outputs. It optimizes
  /// its wallet protocol accordingly.
  pub fn new(view_pair: ViewPair, subaddress: Option<SubaddressIndex>) -> Change {
    Change(Some(ChangeEnum::Standard { view_pair, subaddress }))
  }

  /// Create a change output specification for a guaranteed view pair.
  ///
  /// This take the view key as Monero assumes it has the view key for change outputs. It optimizes
  /// its wallet protocol accordingly.
  pub fn guaranteed(view_pair: GuaranteedViewPair, subaddress: Option<SubaddressIndex>) -> Change {
    Change(Some(ChangeEnum::Guaranteed { view_pair, subaddress }))
  }

  /// Create a fingerprintable change output specification.
  ///
  /// You MUST assume this will harm your privacy. Only use this if you know what you're doing.
  ///
  /// If the change address is Some, this will be unable to optimize the transaction as the
  /// wallet protocol expects it can (due to presumably having the view key for the change
  /// output). If a transaction should be optimized, and isn't, it will be fingerprintable.
  ///
  /// If the change address is None, there are two fingerprints:
  ///
  /// 1) The change in the TX is shunted to the fee (making it fingerprintable).
  ///
  /// 2) In two-output transactions, where the payment address doesn't have a payment ID, wallet2
  ///    includes an encrypted dummy payment ID for the non-change output in order to not allow
  ///    differentiating if transactions send to addresses with payment IDs or not. shekyl-wallet
  ///    includes a dummy payment ID which at least one recipient will identify as not the expected
  ///    dummy payment ID, revealing to the recipient(s) the sender is using non-wallet2 software.
  pub fn fingerprintable(address: Option<ShekylAddress>) -> Change {
    if let Some(address) = address {
      Change(Some(ChangeEnum::AddressOnly(address)))
    } else {
      Change(None)
    }
  }
}

#[allow(private_interfaces)]
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub(crate) enum InternalPayment {
  Payment(ShekylAddress, u64),
  Change(ChangeEnum),
}

impl InternalPayment {
  pub(crate) fn address(&self) -> ShekylAddress {
    match self {
      InternalPayment::Payment(addr, _) => *addr,
      InternalPayment::Change(change) => match change {
        ChangeEnum::AddressOnly(addr) => *addr,
        ChangeEnum::Standard { view_pair, subaddress } => match subaddress {
          Some(subaddress) => view_pair.subaddress(Network::Mainnet, *subaddress),
          None => view_pair.legacy_address(Network::Mainnet),
        },
        ChangeEnum::Guaranteed { view_pair, subaddress } => {
          view_pair.address(Network::Mainnet, *subaddress, None)
        }
      },
    }
  }
}

/// An error while sending a Shekyl transaction.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum SendError {
  /// The proof type for this transaction isn't supported.
  #[error("this library doesn't yet support that ProofType")]
  UnsupportedProofType,
  /// The transaction had no inputs specified.
  #[error("no inputs")]
  NoInputs,
  /// The transaction had no outputs specified.
  #[error("no outputs")]
  NoOutputs,
  /// The transaction had too many outputs specified.
  #[error("too many outputs")]
  TooManyOutputs,
  /// The transaction did not have a change output, and did not have two outputs.
  ///
  /// All transactions must have at least two outputs, assuming one payment and one
  /// change (or at least one dummy and one change).
  #[error("only one output and no change address")]
  NoChange,
  /// Multiple addresses had payment IDs specified.
  ///
  /// Only one payment ID is allowed per transaction.
  #[error("multiple addresses with payment IDs")]
  MultiplePaymentIds,
  /// Too much arbitrary data was specified.
  #[error("too much data")]
  TooMuchArbitraryData,
  /// The created transaction was too large.
  #[error("too large of a transaction")]
  TooLargeTransaction,
  /// The transactions' amounts could not be represented within a `u64`.
  #[error("transaction amounts exceed u64::MAX (in {in_amount}, out {out_amount})")]
  AmountsUnrepresentable {
    /// The amount in (via inputs).
    in_amount: u128,
    /// The amount which would be out (between outputs and the fee).
    out_amount: u128,
  },
  /// This transaction could not pay for itself.
  #[error(
    "not enough funds (inputs {inputs}, outputs {outputs}, necessary_fee {necessary_fee:?})"
  )]
  NotEnoughFunds {
    /// The amount of funds the inputs contributed.
    inputs: u64,
    /// The amount of funds the outputs required.
    outputs: u64,
    /// The fee necessary to be paid on top.
    ///
    /// If this is None, it is because the fee was not calculated as the outputs alone caused this
    /// error.
    necessary_fee: Option<u64>,
  },
  /// This transaction is being signed with the wrong private key.
  #[error("wrong spend private key")]
  WrongPrivateKey,
  /// This transaction was read from a bytestream which was malicious.
  #[error("this SignableTransaction was created by deserializing a malicious serialization")]
  MaliciousSerialization,
  /// The FCMP++ signing flow is not yet implemented in the wallet layer.
  ///
  /// FCMP++ requires a curve tree membership proof and PQC authentication signatures instead
  /// of per-input ring signatures.
  #[error("FCMP++ signing flow not yet implemented")]
  FcmpSigningNotImplemented,
  /// There was an error when working with FROST.
  #[cfg(feature = "multisig")]
  #[error("frost error {0}")]
  FrostError(FrostError),
}

/// A signable transaction.
#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct SignableTransaction {
  pub(crate) proof_type: ProofType,
  outgoing_view_key: Zeroizing<[u8; 32]>,
  pub(crate) inputs: Vec<OutputWithDecoys>,
  pub(crate) payments: Vec<InternalPayment>,
  pub(crate) data: Vec<Vec<u8>>,
  pub(crate) fee_rate: FeeRate,
}

impl fmt::Debug for SignableTransaction {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    f.debug_struct("SignableTransaction")
      .field("proof_type", &self.proof_type)
      .field("inputs", &self.inputs)
      .field("payments", &self.payments)
      .field("data", &self.data)
      .field("fee_rate", &self.fee_rate)
      .finish_non_exhaustive()
  }
}

#[allow(dead_code)]
pub(crate) struct SignableTransactionWithKeyImages {
  pub(crate) intent: SignableTransaction,
  pub(crate) key_images: Vec<CompressedPoint>,
}

impl SignableTransaction {
  fn validate(&self) -> Result<(), SendError> {
    if self.proof_type != ProofType::FcmpPlusPlusPqc {
      return Err(SendError::UnsupportedProofType);
    }

    if self.inputs.is_empty() {
      Err(SendError::NoInputs)?;
    }

    if !self.payments.iter().any(|payment| matches!(payment, InternalPayment::Payment(_, _))) {
      Err(SendError::NoOutputs)?;
    }
    if self.payments.len() < 2 {
      Err(SendError::NoChange)?;
    }
    {
      let mut change_count = 0;
      for payment in &self.payments {
        change_count += usize::from(u8::from(matches!(payment, InternalPayment::Change(_))));
      }
      if change_count > 1 {
        Err(SendError::MaliciousSerialization)?;
      }
    }

    {
      let mut payment_ids = 0;
      for payment in &self.payments {
        payment_ids += usize::from(u8::from(payment.address().payment_id().is_some()));
      }
      if payment_ids > 1 {
        Err(SendError::MultiplePaymentIds)?;
      }
    }

    if self.payments.len() > MAX_BULLETPROOF_COMMITMENTS {
      Err(SendError::TooManyOutputs)?;
    }

    for part in &self.data {
      if part.len() > MAX_ARBITRARY_DATA_SIZE {
        Err(SendError::TooMuchArbitraryData)?;
      }
    }

    if self.extra().len() > MAX_EXTRA_SIZE_BY_RELAY_RULE {
      Err(SendError::TooMuchArbitraryData)?;
    }

    let weight;
    {
      let in_amount: u128 =
        self.inputs.iter().map(|input| u128::from(input.commitment().amount)).sum();
      let payments_amount: u128 = self
        .payments
        .iter()
        .filter_map(|payment| match payment {
          InternalPayment::Payment(_, amount) => Some(u128::from(*amount)),
          InternalPayment::Change(_) => None,
        })
        .sum();
      let necessary_fee;
      (weight, necessary_fee) = self.weight_and_necessary_fee();
      let out_amount = payments_amount + u128::from(necessary_fee);
      let in_out_amount = u64::try_from(in_amount)
        .and_then(|in_amount| u64::try_from(out_amount).map(|out_amount| (in_amount, out_amount)));
      let Ok((in_amount, out_amount)) = in_out_amount else {
        Err(SendError::AmountsUnrepresentable { in_amount, out_amount })?
      };
      if in_amount < out_amount {
        Err(SendError::NotEnoughFunds {
          inputs: in_amount,
          outputs: u64::try_from(payments_amount)
            .expect("total out fit within u64 but not part of total out"),
          necessary_fee: Some(necessary_fee),
        })?;
      }
    }

    const MAX_TX_SIZE: usize = (300_000 / 2) - 600;
    if weight >= MAX_TX_SIZE {
      Err(SendError::TooLargeTransaction)?;
    }

    Ok(())
  }

  /// Create a new SignableTransaction.
  ///
  /// `outgoing_view_key` is used to seed the RNGs for this transaction. Anyone with knowledge of
  /// the outgoing view key will be able to identify a transaction produced with this methodology,
  /// and the data within it. Accordingly, it must be treated as a private key.
  ///
  /// `data` represents arbitrary data which will be embedded into the transaction's `extra` field.
  /// Please see `Extra::arbitrary_data` for the full impacts of this.
  pub fn new(
    proof_type: ProofType,
    outgoing_view_key: Zeroizing<[u8; 32]>,
    inputs: Vec<OutputWithDecoys>,
    payments: Vec<(ShekylAddress, u64)>,
    change: Change,
    data: Vec<Vec<u8>>,
    fee_rate: FeeRate,
  ) -> Result<SignableTransaction, SendError> {
    let mut payments = payments
      .into_iter()
      .map(|(addr, amount)| InternalPayment::Payment(addr, amount))
      .collect::<Vec<_>>();

    if let Some(change) = change.0 {
      payments.push(InternalPayment::Change(change));
    }

    let mut res =
      SignableTransaction { proof_type, outgoing_view_key, inputs, payments, data, fee_rate };
    res.validate()?;

    {
      let mut rng = res.seeded_rng(b"shuffle_payments");
      res.payments.shuffle(&mut rng);
    }

    Ok(res)
  }

  /// The fee rate this transaction uses.
  pub fn fee_rate(&self) -> FeeRate {
    self.fee_rate
  }

  /// The fee this transaction requires.
  ///
  /// This is distinct from the fee this transaction will use. If no change output is specified,
  /// all unspent coins will be shunted to the fee.
  pub fn necessary_fee(&self) -> u64 {
    self.weight_and_necessary_fee().1
  }

  /// Write a SignableTransaction.
  ///
  /// This is not a protocol defined struct, and this is accordingly not a protocol
  /// defined serialization.
  pub fn write<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
    fn write_payment<W: io::Write>(payment: &InternalPayment, w: &mut W) -> io::Result<()> {
      match payment {
        InternalPayment::Payment(addr, amount) => {
          w.write_all(&[0])?;
          write_vec(write_byte, addr.to_string().as_bytes(), w)?;
          w.write_all(&amount.to_le_bytes())
        }
        InternalPayment::Change(change) => match change {
          ChangeEnum::AddressOnly(addr) => {
            w.write_all(&[1])?;
            write_vec(write_byte, addr.to_string().as_bytes(), w)
          }
          ChangeEnum::Standard { view_pair, subaddress } => {
            w.write_all(&[2])?;
            write_point(&view_pair.spend(), w)?;
            write_scalar(&view_pair.view, w)?;
            if let Some(subaddress) = subaddress {
              w.write_all(&subaddress.account().to_le_bytes())?;
              w.write_all(&subaddress.address().to_le_bytes())
            } else {
              w.write_all(&0u32.to_le_bytes())?;
              w.write_all(&0u32.to_le_bytes())
            }
          }
          ChangeEnum::Guaranteed { view_pair, subaddress } => {
            w.write_all(&[3])?;
            write_point(&view_pair.spend(), w)?;
            write_scalar(&view_pair.0.view, w)?;
            if let Some(subaddress) = subaddress {
              w.write_all(&subaddress.account().to_le_bytes())?;
              w.write_all(&subaddress.address().to_le_bytes())
            } else {
              w.write_all(&0u32.to_le_bytes())?;
              w.write_all(&0u32.to_le_bytes())
            }
          }
        },
      }
    }

    write_byte(&u8::from(self.proof_type), w)?;
    w.write_all(self.outgoing_view_key.as_slice())?;
    write_vec(OutputWithDecoys::write, &self.inputs, w)?;
    write_vec(write_payment, &self.payments, w)?;
    write_vec(|data, w| write_vec(write_byte, data, w), &self.data, w)?;
    self.fee_rate.write(w)
  }

  /// Serialize the SignableTransaction to a `Vec<u8>`.
  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    self.write(&mut buf).expect("write failed but <Vec as io::Write> doesn't fail");
    buf
  }

  /// Read a `SignableTransaction`.
  pub fn read<R: io::Read>(r: &mut R) -> io::Result<SignableTransaction> {
    fn read_address<R: io::Read>(r: &mut R) -> io::Result<ShekylAddress> {
      const FEATURED_ADDRESS_DATA_SIZE_UPPER_BOUND: usize = 9 + 32 + 32 + 9 + 8;
      const FEATURED_ADDRESS_CHECKED_DATA_SIZE_UPPER_BOUND: usize =
        FEATURED_ADDRESS_DATA_SIZE_UPPER_BOUND + 4;
      const FEATURED_ADDRESS_ENCODED_SIZE_UPPER_BOUND: usize =
        (FEATURED_ADDRESS_CHECKED_DATA_SIZE_UPPER_BOUND * 8).div_ceil(5);
      const JAMTIS_ADDRESS_ENCODED_SIZE: usize = 247;
      const fn const_max(a: usize, b: usize) -> usize {
        if a > b {
          a
        } else {
          b
        }
      }
      const ADDRESS_ENCODED_SIZE_UPPER_BOUND: usize =
        const_max(FEATURED_ADDRESS_ENCODED_SIZE_UPPER_BOUND, JAMTIS_ADDRESS_ENCODED_SIZE);
      const ADDRESS_ENCODED_SIZE_SAFETY_FACTOR: usize = 2;
      const ADDRESS_ENCODED_SIZE_BOUND: usize =
        ADDRESS_ENCODED_SIZE_SAFETY_FACTOR * ADDRESS_ENCODED_SIZE_UPPER_BOUND;

      String::from_utf8(read_vec(read_byte, Some(ADDRESS_ENCODED_SIZE_BOUND), r)?)
        .ok()
        .and_then(|str| ShekylAddress::from_str_with_unchecked_network(&str).ok())
        .ok_or_else(|| io::Error::other("invalid address"))
    }

    fn read_payment<R: io::Read>(r: &mut R) -> io::Result<InternalPayment> {
      Ok(match read_byte(r)? {
        0 => InternalPayment::Payment(read_address(r)?, read_u64(r)?),
        1 => InternalPayment::Change(ChangeEnum::AddressOnly(read_address(r)?)),
        2 => InternalPayment::Change(ChangeEnum::Standard {
          view_pair: ViewPair::new(read_point(r)?, Zeroizing::new(read_scalar(r)?))
            .map_err(io::Error::other)?,
          subaddress: SubaddressIndex::new(read_u32(r)?, read_u32(r)?),
        }),
        3 => InternalPayment::Change(ChangeEnum::Guaranteed {
          view_pair: GuaranteedViewPair::new(read_point(r)?, Zeroizing::new(read_scalar(r)?))
            .map_err(io::Error::other)?,
          subaddress: SubaddressIndex::new(read_u32(r)?, read_u32(r)?),
        }),
        _ => Err(io::Error::other("invalid payment"))?,
      })
    }

    let res = SignableTransaction {
      proof_type: ProofType::try_from(read_byte(r)?)
        .map_err(|()| io::Error::other("unsupported/invalid ProofType"))?,
      outgoing_view_key: Zeroizing::new(read_bytes(r)?),
      inputs: read_vec(OutputWithDecoys::read, Some(INPUTS_UPPER_BOUND), r)?,
      payments: read_vec(read_payment, Some(MAX_BULLETPROOF_COMMITMENTS), r)?,
      data: read_vec(
        |r| read_vec(read_byte, Some(MAX_ARBITRARY_DATA_SIZE), r),
        Some(MAX_EXTRA_SIZE_BY_RELAY_RULE),
        r,
      )?,
      fee_rate: FeeRate::read(r)?,
    };
    match res.validate() {
      Ok(()) => {}
      Err(e) => Err(io::Error::other(e))?,
    }
    Ok(res)
  }

  #[allow(dead_code)]
  fn with_key_images(
    mut self,
    key_images: Vec<CompressedPoint>,
  ) -> SignableTransactionWithKeyImages {
    debug_assert_eq!(self.inputs.len(), key_images.len());

    let mut sorted_inputs = self.inputs.into_iter().zip(key_images).collect::<Vec<_>>();
    sorted_inputs
      .sort_by(|(_, key_image_a), (_, key_image_b)| key_image_sort(key_image_a, key_image_b));

    self.inputs = Vec::with_capacity(sorted_inputs.len());
    let mut key_images = Vec::with_capacity(sorted_inputs.len());
    for (input, key_image) in sorted_inputs {
      self.inputs.push(input);
      key_images.push(key_image);
    }

    SignableTransactionWithKeyImages { intent: self, key_images }
  }

  /// Sign this transaction.
  ///
  /// FCMP++ signing is not yet implemented. This method will return
  /// `SendError::FcmpSigningNotImplemented` for all transactions until the FCMP++ signing
  /// flow (curve tree membership proof + PQC authentication) is complete.
  pub fn sign(
    self,
    _rng: &mut (impl RngCore + CryptoRng),
    _sender_spend_key: &Zeroizing<Scalar>,
  ) -> Result<Transaction, SendError> {
    Err(SendError::FcmpSigningNotImplemented)
  }
}
