// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet context: owns the wallet2 FFI handle and provides command-friendly methods.

use shekyl_wallet_rpc::{Wallet2, WalletError};

pub struct WalletContext {
    wallet: Wallet2,
}

impl WalletContext {
    pub fn new(
        nettype: u8,
        daemon_address: &str,
        daemon_user: &str,
        daemon_pass: &str,
        trusted_daemon: bool,
        wallet_dir: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let wallet =
            Wallet2::new(nettype).map_err(|e| format!("Failed to create wallet handle: {e}"))?;
        wallet.set_wallet_dir(wallet_dir);
        if !daemon_address.is_empty() {
            wallet
                .init(daemon_address, daemon_user, daemon_pass, trusted_daemon)
                .map_err(|e| format!("Failed to connect to daemon: {e}"))?;
        }
        Ok(Self { wallet })
    }

    pub fn is_open(&self) -> bool {
        self.wallet.is_open()
    }

    pub fn create(
        &self,
        filename: &str,
        password: &str,
        language: &str,
    ) -> Result<(), WalletError> {
        self.wallet.create_wallet(filename, password, language)
    }

    pub fn open(&self, filename: &str, password: &str) -> Result<(), WalletError> {
        self.wallet.open_wallet(filename, password)
    }

    pub fn close(&self) -> Result<(), WalletError> {
        self.wallet.close_wallet(true)
    }

    pub fn refresh(&self) -> Result<(), WalletError> {
        self.wallet.refresh()
    }

    pub fn store(&self) -> Result<(), WalletError> {
        self.wallet.store()
    }

    pub fn get_balance(&self, account_index: u32) -> Result<serde_json::Value, WalletError> {
        self.wallet.get_balance(account_index)
    }

    pub fn get_address(&self, account_index: u32) -> Result<serde_json::Value, WalletError> {
        self.wallet.get_address(account_index)
    }

    pub fn transfer(
        &self,
        destinations_json: &str,
        priority: u32,
        account_index: u32,
    ) -> Result<serde_json::Value, WalletError> {
        self.wallet
            .transfer_native(destinations_json, priority, account_index)
    }

    pub fn query_key(&self, key_type: &str) -> Result<serde_json::Value, WalletError> {
        self.wallet.query_key(key_type)
    }

    pub fn get_height(&self) -> u64 {
        self.wallet.get_height()
    }

    pub fn get_transfers(
        &self,
        incoming: bool,
        outgoing: bool,
        pending: bool,
        failed: bool,
        pool: bool,
        account_index: u32,
    ) -> Result<serde_json::Value, WalletError> {
        self.wallet
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
    ) -> Result<serde_json::Value, WalletError> {
        self.wallet.restore_deterministic_wallet(
            filename,
            seed,
            password,
            language,
            restore_height,
            seed_offset,
        )
    }

    pub fn json_rpc(&self, method: &str, params: &str) -> Result<serde_json::Value, WalletError> {
        self.wallet.json_rpc_call(method, params)
    }
}
