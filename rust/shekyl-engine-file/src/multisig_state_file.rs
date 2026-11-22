// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `.wallet.multisig`: a group wallet's ceremony records (R-30;
//! `docs/WALLET_FILE_FORMAT_V1.md`, `PayloadKind` `0x04`).
//!
//! Sealed and opened as `.wallet.pscan` and `.wallet.pending` are: the same
//! region-2 envelope under the session-cached `wrap_key_region_2`, a
//! distinct payload kind so a swapped sibling is a loud refusal, and a
//! crash-atomic write-then-rename. The body is a postcard-encoded
//! `shekyl_engine_state::MultisigState`; the engine layer owns its
//! serialization.

use std::io;
use std::path::PathBuf;

use shekyl_crypto_pq::wallet_envelope::{
    open_state_file_with_wrap_key_region_2, seal_state_file_with_wrap_key_region_2,
};

use super::{WalletFile, FILE_KEK_BYTES};
use crate::atomic::{atomic_write_file, Durability};
use crate::error::WalletFileError;
use crate::paths::multisig_state_path_from;
use crate::payload::{decode_payload, encode_payload, PayloadKind};

impl WalletFile {
    /// The `.wallet.multisig` path: a sibling of the state file.
    #[must_use]
    pub fn multisig_path(&self) -> PathBuf {
        multisig_state_path_from(&self.state_path)
    }

    /// Persist a group wallet's ceremony records to `.wallet.multisig`
    /// under the session-cached `wrap_key_region_2`. `body` is the
    /// postcard-encoded `MultisigState`. Crash-atomic: a reservation is
    /// durable before the nonce it guards exists.
    pub fn save_multisig_state(
        &self,
        wrap_key_region_2: &[u8; FILE_KEK_BYTES],
        body: &[u8],
    ) -> Result<Durability, WalletFileError> {
        let framed = encode_payload(PayloadKind::MultisigStatePostcard, body)?;
        let keys_file_bytes = self
            .state
            .lock()
            .expect("wallet file mutex poisoned")
            .keys_file_bytes
            .clone();
        let sealed =
            seal_state_file_with_wrap_key_region_2(wrap_key_region_2, &keys_file_bytes, &framed)?;
        atomic_write_file(&self.multisig_path(), &sealed)
    }

    /// Load a group wallet's ceremony records from `.wallet.multisig`.
    ///
    /// Returns `Ok(None)` when the file does not exist yet: a group wallet
    /// before its first ceremony, whose caller starts from
    /// `MultisigState::empty()`. Refuses a wrong payload kind
    /// ([`WalletFileError::UnexpectedPayloadKind`]): the swap guard.
    pub fn open_multisig_state(
        &self,
        wrap_key_region_2: &[u8; FILE_KEK_BYTES],
    ) -> Result<Option<Vec<u8>>, WalletFileError> {
        let file_bytes = match std::fs::read(self.multisig_path()) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(WalletFileError::Io(e)),
        };
        let keys_file_bytes = self
            .state
            .lock()
            .expect("wallet file mutex poisoned")
            .keys_file_bytes
            .clone();
        let framed = open_state_file_with_wrap_key_region_2(
            wrap_key_region_2,
            &keys_file_bytes,
            &file_bytes,
        )?;
        let decoded = decode_payload(&framed)?;
        if decoded.payload_kind != PayloadKind::MultisigStatePostcard {
            return Err(WalletFileError::UnexpectedPayloadKind {
                expected: PayloadKind::MultisigStatePostcard as u8,
                got: decoded.payload_kind as u8,
            });
        }
        Ok(Some(decoded.body.to_vec()))
    }
}
