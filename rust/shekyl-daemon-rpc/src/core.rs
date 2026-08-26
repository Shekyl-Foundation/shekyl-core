// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Thread-safe wrapper over the C++ core_rpc_server FFI handle.

use crate::ffi;
use std::ffi::{CStr, CString};

/// Wrapper around the opaque `core_rpc_handle` pointer.
/// The handle borrows an existing `core_rpc_server` owned by the C++ daemon.
///
/// All methods are `&self` because the underlying C++ handlers are already
/// designed for concurrent access (epee's thread pool model). The FFI calls
/// block on the C++ side, so Axum dispatches them via `spawn_blocking`.
pub struct CoreRpc {
    handle: *mut ffi::CoreRpcHandle,
}

// The C++ core_rpc_server handlers use internal locks for thread safety.
unsafe impl Send for CoreRpc {}
unsafe impl Sync for CoreRpc {}

impl CoreRpc {
    /// Wrap a raw `core_rpc_server*` obtained from C++.
    ///
    /// # Safety
    /// `rpc_server_ptr` must point to a live, fully-initialized `core_rpc_server`
    /// that outlives this `CoreRpc`.
    pub unsafe fn from_raw(rpc_server_ptr: *mut std::ffi::c_void) -> Option<Self> {
        let handle = unsafe { ffi::core_rpc_ffi_create(rpc_server_ptr) };
        if handle.is_null() {
            None
        } else {
            Some(Self { handle })
        }
    }

    /// Dispatch a JSON REST endpoint (e.g. "/get_info").
    pub fn json_endpoint(&self, uri: &str, body: &str) -> Option<String> {
        if self.handle.is_null() {
            return None;
        }
        let c_uri = CString::new(uri).ok()?;
        let c_body = CString::new(body).ok()?;
        unsafe {
            let ptr = ffi::core_rpc_ffi_json_endpoint(self.handle, c_uri.as_ptr(), c_body.as_ptr());
            consume_c_string(ptr)
        }
    }

    /// §55: relay stem-outcome tallies as a JSON array string.
    ///
    /// Not routed through [`Self::json_endpoint`] because the data does not
    /// live in `core_rpc_server` — it lives in the relay zones, and this is
    /// the shortest path to it while C++ owns their lifetime.
    pub fn stem_tallies(&self) -> Option<String> {
        if self.handle.is_null() {
            return None;
        }
        unsafe { consume_c_string(ffi::core_rpc_ffi_stem_tallies(self.handle)) }
    }

    /// Raw handle for the submit shims (`crate::submit::ffi_shim`), which
    /// call the `shekyl_submit_*` FFI directly rather than through the
    /// string-dispatch surface above.
    pub(crate) fn raw_handle(&self) -> *mut ffi::CoreRpcHandle {
        self.handle
    }

    /// Chain-tip facts (`shekyl_rpc_chain_tip`); `Err(code)` on a non-OK
    /// return, including a null handle.
    pub fn chain_tip(&self) -> Result<ffi::ChainTipFactsFfi, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut pod = ffi::ChainTipFactsFfi {
            chain_height: 0,
            top_hash: [0; 32],
            target_height: 0,
            synchronized: 0,
            release_build: 0,
            reserved: [0; 6],
        };
        // SAFETY: live handle; `pod` is a valid out pointer for the call.
        let rc = unsafe { ffi::shekyl_rpc_chain_tip(self.handle, &raw mut pod) };
        if rc == ffi::SHEKYL_RPC_FACTS_OK {
            Ok(pod)
        } else {
            Err(rc)
        }
    }

    /// Block hash at `height` plus the tip as of the same read
    /// (`shekyl_rpc_block_hash_at`); `Err(code)` on a non-OK return.
    pub fn block_hash_at(&self, height: u64) -> Result<ffi::BlockHashFactsFfi, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut pod = ffi::BlockHashFactsFfi {
            hash: [0; 32],
            chain_height: 0,
            found: 0,
            reserved: [0; 7],
        };
        // SAFETY: live handle; `pod` is a valid out pointer for the call.
        let rc = unsafe { ffi::shekyl_rpc_block_hash_at(self.handle, height, &raw mut pod) };
        if rc == ffi::SHEKYL_RPC_FACTS_OK {
            Ok(pod)
        } else {
            Err(rc)
        }
    }

    /// The block-header projection at `height` (`shekyl_rpc_block_header_at`);
    /// `Err(code)` on a non-OK return.
    pub fn block_header_at(
        &self,
        height: u64,
        fill_pow_hash: bool,
    ) -> Result<ffi::BlockHeaderFactsFfi, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut pod = ffi::BlockHeaderFactsFfi::zeroed();
        // SAFETY: live handle; `pod` is a valid out pointer for the call.
        let rc = unsafe {
            ffi::shekyl_rpc_block_header_at(
                self.handle,
                height,
                u8::from(fill_pow_hash),
                &raw mut pod,
            )
        };
        if rc == ffi::SHEKYL_RPC_FACTS_OK {
            Ok(pod)
        } else {
            Err(rc)
        }
    }

    /// The hard-fork schedule (`shekyl_rpc_hardforks`), copied out of the
    /// C++-owned view before it is released.
    pub fn hardforks(&self) -> Result<Vec<ffi::HardforkEntryFfi>, i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut rows: *const ffi::HardforkEntryFfi = std::ptr::null();
        let mut len: usize = 0;
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: live handle; the three out pointers are valid; on OK the
        // view is valid until `shekyl_rpc_hardforks_free(owner)`.
        unsafe {
            let rc =
                ffi::shekyl_rpc_hardforks(self.handle, &raw mut rows, &raw mut len, &raw mut owner);
            if rc != ffi::SHEKYL_RPC_FACTS_OK {
                return Err(rc);
            }
            let copied = if rows.is_null() || len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(rows, len).to_vec()
            };
            ffi::shekyl_rpc_hardforks_free(owner);
            Ok(copied)
        }
    }

    /// A whole block by hash, or by height when `block_hash` is `None`.
    ///
    /// Returns the header POD alongside owned copies of the three
    /// variable-length payloads. The C++ owner is released **in this
    /// function**, before any of the fallible work above it can return early
    /// — the reason the copies are made rather than the borrows returned.
    #[allow(clippy::type_complexity)]
    pub fn block_at(
        &self,
        block_hash: Option<&[u8; 32]>,
        height: u64,
        fill_pow_hash: bool,
    ) -> Result<(ffi::BlockHeaderFactsFfi, Vec<u8>, String, Vec<[u8; 32]>), i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut header = ffi::BlockHeaderFactsFfi::zeroed();
        let mut payload = ffi::BlockPayloadFfi::default();
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: live handle; the out pointers are valid for the call. On OK
        // with a found block the payload borrows memory owned by `owner`,
        // which is released below before this function returns — every copy
        // is taken first, and nothing fallible runs between.
        unsafe {
            let rc = ffi::shekyl_rpc_block_at(
                self.handle,
                block_hash.map_or(std::ptr::null(), |h| h.as_ptr()),
                height,
                u8::from(fill_pow_hash),
                &raw mut header,
                &raw mut payload,
                &raw mut owner,
            );
            if rc != ffi::SHEKYL_RPC_FACTS_OK {
                return Err(rc);
            }
            let blob = if payload.blob.is_null() || payload.blob_len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(payload.blob, payload.blob_len).to_vec()
            };
            let json = if payload.json.is_null() || payload.json_len == 0 {
                String::new()
            } else {
                String::from_utf8_lossy(std::slice::from_raw_parts(
                    payload.json.cast::<u8>(),
                    payload.json_len,
                ))
                .into_owned()
            };
            // `len * 32` is the length handed to `from_raw_parts`, where a
            // wrong value is immediate UB rather than a bad answer — so it is
            // checked, and the pointer is checked before anything is sized
            // from the length. Nothing here returns early: the owner must be
            // released on every path out, so the verdict comes after the free.
            let tx_bytes = payload.tx_hashes_len.checked_mul(32);
            let tx_hashes: Vec<[u8; 32]> = match tx_bytes {
                Some(n) if n > 0 && !payload.tx_hashes.is_null() => {
                    std::slice::from_raw_parts(payload.tx_hashes, n)
                        .chunks_exact(32)
                        .map(|chunk| {
                            let mut one = [0u8; 32];
                            one.copy_from_slice(chunk);
                            one
                        })
                        .collect()
                }
                _ => Vec::new(),
            };
            ffi::shekyl_rpc_block_free(owner);
            if tx_bytes.is_none() {
                // Only reachable if the export ever reported a length no
                // allocation could have produced. Refuse rather than answer
                // with the block's transactions silently dropped.
                return Err(ffi::SHEKYL_RPC_FACTS_ERR_INTERNAL);
            }
            Ok((header, blob, json, tx_hashes))
        }
    }

    /// Global output indices of one transaction, and whether the store had
    /// the transaction at all.
    ///
    /// The owner is released in this function, after the copy and before any
    /// verdict, so no path out can lose the free.
    pub fn tx_output_indices(&self, txid: &[u8; 32]) -> Result<(Vec<u64>, bool), i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut rows: *const u64 = std::ptr::null();
        let mut len: usize = 0;
        let mut found: u8 = 0;
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: live handle; every out pointer is valid for the call. On OK
        // the view borrows memory owned by `owner`, released below.
        unsafe {
            let rc = ffi::shekyl_rpc_tx_output_indices(
                self.handle,
                txid.as_ptr(),
                &raw mut rows,
                &raw mut len,
                &raw mut found,
                &raw mut owner,
            );
            if rc != ffi::SHEKYL_RPC_FACTS_OK {
                return Err(rc);
            }
            let copied = if rows.is_null() || len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(rows, len).to_vec()
            };
            ffi::shekyl_rpc_tx_output_indices_free(owner);
            Ok((copied, found != 0))
        }
    }

    /// Blocks at `heights`, in order.
    ///
    /// Returns the entries gathered and, when the chain could not produce a
    /// height, that height alongside them.
    ///
    /// The two are not exclusive: a failure keeps the blocks read **before**
    /// it, because the C++ did — it cleared its list once before the loop and
    /// returned from the failure without clearing again, so `[0, past_tip]`
    /// carried block 0 with the error. The owner is released here, after the
    /// copies and before any verdict, so no path out can lose the free.
    pub fn blocks_by_height(
        &self,
        heights: &[u64],
    ) -> Result<(Vec<shekyl_rpc_types::BlockEntry>, Option<u64>), i32> {
        if self.handle.is_null() {
            return Err(ffi::SHEKYL_RPC_FACTS_ERR_NULL);
        }
        let mut rows: *const ffi::BlockEntryFfi = std::ptr::null();
        let mut len: usize = 0;
        let mut failed_height: u64 = 0;
        let mut ok: u8 = 0;
        let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: live handle; every out pointer is valid for the call. On OK
        // the views borrow memory owned by `owner`, released below before
        // this function returns, with every copy taken first.
        unsafe {
            let rc = ffi::shekyl_rpc_blocks_by_height(
                self.handle,
                if heights.is_empty() {
                    std::ptr::null()
                } else {
                    heights.as_ptr()
                },
                heights.len(),
                &raw mut rows,
                &raw mut len,
                &raw mut failed_height,
                &raw mut ok,
                &raw mut owner,
            );
            if rc != ffi::SHEKYL_RPC_FACTS_OK {
                return Err(rc);
            }
            // Past this point an owner may exist, so nothing returns until
            // it is released. The entries are copied whether or not `ok` is
            // set: on a failure they are the prefix the C++ also returned.
            let mut out = Vec::with_capacity(len);
            if !rows.is_null() {
                for entry in std::slice::from_raw_parts(rows, len) {
                    let block = if entry.block.is_null() || entry.block_len == 0 {
                        Vec::new()
                    } else {
                        std::slice::from_raw_parts(entry.block, entry.block_len).to_vec()
                    };
                    let mut txs = Vec::with_capacity(entry.tx_count);
                    if !entry.txs.is_null() && !entry.tx_lens.is_null() {
                        let ptrs = std::slice::from_raw_parts(entry.txs, entry.tx_count);
                        let lens = std::slice::from_raw_parts(entry.tx_lens, entry.tx_count);
                        for (p, l) in ptrs.iter().zip(lens.iter()) {
                            txs.push(if p.is_null() || *l == 0 {
                                Vec::new()
                            } else {
                                std::slice::from_raw_parts(*p, *l).to_vec()
                            });
                        }
                    }
                    out.push(shekyl_rpc_types::BlockEntry { block, txs });
                }
            }
            ffi::shekyl_rpc_blocks_by_height_free(owner);
            Ok((out, (ok == 0).then_some(failed_height)))
        }
    }

    /// Dispatch a JSON-RPC 2.0 method.
    /// Returns the raw response string from C++ (contains ok/error envelope).
    pub fn json_rpc(&self, method: &str, params: &str) -> Option<String> {
        if self.handle.is_null() {
            return None;
        }
        let c_method = CString::new(method).ok()?;
        let c_params = CString::new(params).ok()?;
        unsafe {
            let ptr = ffi::core_rpc_ffi_json_rpc(self.handle, c_method.as_ptr(), c_params.as_ptr());
            consume_c_string(ptr)
        }
    }
}

impl Drop for CoreRpc {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { ffi::core_rpc_ffi_destroy(self.handle) };
        }
    }
}

#[cfg(test)]
impl CoreRpc {
    /// Null-handle stand-in reserved for future router tests that never reach FFI.
    #[allow(dead_code)]
    pub(crate) fn null_for_router_tests() -> Self {
        Self {
            handle: std::ptr::null_mut(),
        }
    }
}

/// Take ownership of a C-allocated string, copy it into a Rust String, and free the C side.
unsafe fn consume_c_string(ptr: *mut std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    unsafe { ffi::core_rpc_ffi_free_string(ptr) };
    Some(s)
}
