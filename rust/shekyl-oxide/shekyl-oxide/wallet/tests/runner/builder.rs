use zeroize::{Zeroize, Zeroizing};

use shekyl_wallet::{
  fcmp::ProofType,
  rpc::FeeRate,
  address::ShekylAddress,
  OutputWithDecoys,
  send::{Change, SendError, SignableTransaction},
  extra::MAX_ARBITRARY_DATA_SIZE,
};

/// A builder for Monero transactions.
#[derive(Clone, PartialEq, Eq, Zeroize, Debug)]
pub struct SignableTransactionBuilder {
  proof_type: ProofType,
  outgoing_view_key: Zeroizing<[u8; 32]>,
  inputs: Vec<OutputWithDecoys>,
  payments: Vec<(ShekylAddress, u64)>,
  change: Change,
  data: Vec<Vec<u8>>,
  fee_rate: FeeRate,
}

impl SignableTransactionBuilder {
  pub fn new(
    proof_type: ProofType,
    outgoing_view_key: Zeroizing<[u8; 32]>,
    change: Change,
    fee_rate: FeeRate,
  ) -> Self {
    Self {
      proof_type,
      outgoing_view_key,
      inputs: vec![],
      payments: vec![],
      change,
      data: vec![],
      fee_rate,
    }
  }

  pub fn add_input(&mut self, input: OutputWithDecoys) -> &mut Self {
    self.inputs.push(input);
    self
  }
  #[allow(unused)]
  pub fn add_inputs(&mut self, inputs: &[OutputWithDecoys]) -> &mut Self {
    self.inputs.extend(inputs.iter().cloned());
    self
  }

  pub fn add_payment(&mut self, dest: ShekylAddress, amount: u64) -> &mut Self {
    self.payments.push((dest, amount));
    self
  }
  #[allow(unused)]
  pub fn add_payments(&mut self, payments: &[(ShekylAddress, u64)]) -> &mut Self {
    self.payments.extend(payments);
    self
  }

  #[allow(unused)]
  pub fn add_data(&mut self, data: Vec<u8>) -> Result<&mut Self, SendError> {
    if data.len() > MAX_ARBITRARY_DATA_SIZE {
      Err(SendError::TooMuchArbitraryData)?;
    }
    self.data.push(data);
    Ok(self)
  }

  pub fn build(self) -> Result<SignableTransaction, SendError> {
    SignableTransaction::new(
      self.proof_type,
      self.outgoing_view_key,
      self.inputs,
      self.payments,
      self.change,
      self.data,
      self.fee_rate,
    )
  }
}
