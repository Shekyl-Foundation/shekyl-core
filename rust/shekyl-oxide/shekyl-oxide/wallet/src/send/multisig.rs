use std_shims::{
  vec::Vec,
  io::{self, Read},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::EdwardsPoint;

use transcript::{Transcript, RecommendedTranscript};
use frost::{
  curve::Ed25519,
  Participant, FrostError, ThresholdKeys,
  sign::{
    Writable, Preprocess, CachedPreprocess, SignatureShare, PreprocessMachine, SignMachine,
    SignatureMachine,
  },
};

use shekyl_oxide::transaction::Transaction;
use crate::send::{SendError, SignableTransaction};

/// Initial FROST machine to produce a signed transaction.
///
/// FCMP++ multisig signing (FROST-based threshold membership proof) is not yet
/// implemented. Calling `preprocess` will produce a stub that cannot complete
/// signing.
pub struct TransactionMachine {
  _signable: SignableTransaction,
  _keys: ThresholdKeys<Ed25519>,
}

/// Second FROST machine (stub -- FCMP++ multisig not yet implemented).
pub struct TransactionSignMachine {
  _phantom: (),
}

/// Final FROST machine (stub -- FCMP++ multisig not yet implemented).
pub struct TransactionSignatureMachine {
  _phantom: (),
}

impl SignableTransaction {
  /// Create a FROST signing machine out of this signable transaction.
  ///
  /// FCMP++ multisig is not yet implemented. This will always return
  /// `SendError::FcmpSigningNotImplemented`.
  pub fn multisig(self, _keys: ThresholdKeys<Ed25519>) -> Result<TransactionMachine, SendError> {
    Err(SendError::FcmpSigningNotImplemented)
  }
}

/// The preprocess for a transaction (stub).
#[derive(Clone, PartialEq)]
pub struct TransactionPreprocess(Vec<u8>);
impl Writable for TransactionPreprocess {
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.0)
  }
}

/// The signature share for a transaction (stub).
#[derive(Clone, PartialEq)]
pub struct TransactionSignatureShare(Vec<u8>);
impl Writable for TransactionSignatureShare {
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.0)
  }
}

impl PreprocessMachine for TransactionMachine {
  type Preprocess = TransactionPreprocess;
  type Signature = Transaction;
  type SignMachine = TransactionSignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    self,
    _rng: &mut R,
  ) -> (TransactionSignMachine, Self::Preprocess) {
    unimplemented!("FCMP++ multisig signing is not yet implemented")
  }
}

impl SignMachine<Transaction> for TransactionSignMachine {
  type Params = ();
  type Keys = ThresholdKeys<Ed25519>;
  type Preprocess = TransactionPreprocess;
  type SignatureShare = TransactionSignatureShare;
  type SignatureMachine = TransactionSignatureMachine;

  fn cache(self) -> CachedPreprocess {
    unimplemented!("FCMP++ multisig signing is not yet implemented")
  }

  fn from_cache(
    (): (),
    _: ThresholdKeys<Ed25519>,
    _: CachedPreprocess,
  ) -> (Self, Self::Preprocess) {
    unimplemented!("FCMP++ multisig signing is not yet implemented")
  }

  fn read_preprocess<R: Read>(&self, _reader: &mut R) -> io::Result<Self::Preprocess> {
    Err(io::Error::other("FCMP++ multisig signing is not yet implemented"))
  }

  fn sign(
    self,
    _commitments: HashMap<Participant, Self::Preprocess>,
    _msg: &[u8],
  ) -> Result<(TransactionSignatureMachine, Self::SignatureShare), FrostError> {
    Err(FrostError::InternalError("FCMP++ multisig signing is not yet implemented"))
  }
}

impl SignatureMachine<Transaction> for TransactionSignatureMachine {
  type SignatureShare = TransactionSignatureShare;

  fn read_share<R: Read>(&self, _reader: &mut R) -> io::Result<Self::SignatureShare> {
    Err(io::Error::other("FCMP++ multisig signing is not yet implemented"))
  }

  fn complete(
    self,
    _shares: HashMap<Participant, Self::SignatureShare>,
  ) -> Result<Transaction, FrostError> {
    Err(FrostError::InternalError("FCMP++ multisig signing is not yet implemented"))
  }
}
