// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Engine context: owns the Wallet2 FFI handle and provides command-friendly methods.

use shekyl_engine_rpc::{Wallet2, EngineError};
use std::path::PathBuf;

pub struct EngineContext {
    wallet2: Wallet2,
    engine_dir: PathBuf,
}

impl EngineContext {
    pub fn new(
        nettype: u8,
        daemon_address: &str,
        daemon_user: &str,
        daemon_pass: &str,
        trusted_daemon: bool,
        engine_dir: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let wallet2 =
            Wallet2::new(nettype).map_err(|e| format!("Failed to create engine handle: {e}"))?;
        if !daemon_address.is_empty() {
            wallet2
                .init(daemon_address, daemon_user, daemon_pass, trusted_daemon)
                .map_err(|e| format!("Failed to connect to daemon: {e}"))?;
        }
        Ok(Self {
            wallet2,
            engine_dir: PathBuf::from(engine_dir),
        })
    }

    fn join_path(&self, filename: &str) -> String {
        self.engine_dir.join(filename).to_string_lossy().to_string()
    }

    pub fn is_open(&self) -> bool {
        self.wallet2.is_open()
    }

    pub fn create(
        &self,
        filename: &str,
        password: &str,
        language: &str,
    ) -> Result<(), EngineError> {
        let path = self.join_path(filename);
        self.wallet2.create_wallet(&path, password, language)
    }

    pub fn open(&self, filename: &str, password: &str) -> Result<(), EngineError> {
        let path = self.join_path(filename);
        self.wallet2.open_wallet(&path, password)
    }

    pub fn close(&self) -> Result<(), EngineError> {
        self.wallet2.close_wallet(true)
    }

    pub fn refresh(&self) -> Result<(), EngineError> {
        self.wallet2.refresh()
    }

    pub fn store(&self) -> Result<(), EngineError> {
        self.wallet2.store()
    }

    pub fn get_balance(&self, account_index: u32) -> Result<serde_json::Value, EngineError> {
        self.wallet2.get_balance(account_index)
    }

    pub fn get_address(&self, account_index: u32) -> Result<serde_json::Value, EngineError> {
        self.wallet2.get_address(account_index)
    }

    pub fn transfer(
        &self,
        destinations_json: &str,
        priority: u32,
        account_index: u32,
    ) -> Result<serde_json::Value, EngineError> {
        self.wallet2
            .transfer_native(destinations_json, priority, account_index)
    }

    pub fn query_key(&self, key_type: &str) -> Result<serde_json::Value, EngineError> {
        self.wallet2.query_key(key_type)
    }

    pub fn get_height(&self) -> u64 {
        self.wallet2.get_height()
    }

    pub fn get_transfers(
        &self,
        incoming: bool,
        outgoing: bool,
        pending: bool,
        failed: bool,
        pool: bool,
        account_index: u32,
    ) -> Result<serde_json::Value, EngineError> {
        self.wallet2
            .get_transfers(incoming, outgoing, pending, failed, pool, account_index)
    }

    pub fn restore_from_seed(
        &self,
        filename: &str,
        seed: &str,
        password: &str,
        language: &str,
        restore_height: u64,
        seed_offset: &str,
    ) -> Result<serde_json::Value, EngineError> {
        let path = self.join_path(filename);
        self.wallet2.restore_deterministic_wallet(
            &path,
            seed,
            password,
            language,
            restore_height,
            seed_offset,
        )
    }

    pub fn json_rpc(&self, method: &str, params: &str) -> Result<serde_json::Value, EngineError> {
        self.wallet2.json_rpc_call(method, params)
    }
}
