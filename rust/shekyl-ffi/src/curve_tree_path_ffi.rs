// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Coarse FFI for daemon RPC membership-path assembly.
//!
//! C++ supplies store reads as callbacks; Rust owns the byte layout, the
//! boundary-chunk trim, and the fail-closed contract (PDM-Q-F9).

use std::os::raw::c_void;

use shekyl_fcmp::rpc_path::{assemble_rpc_path, PathAssembleError, PathStore, LEAF_BYTES};

use super::legacy_types::ShekylBuffer;

pub type ShekylCtReadLeafFn =
    unsafe extern "C" fn(ctx: *mut c_void, pos: u64, leaf_out: *mut u8) -> bool;
pub type ShekylCtReadLayerHashFn =
    unsafe extern "C" fn(ctx: *mut c_void, layer: u8, chunk: u64, hash_out: *mut u8) -> bool;
pub type ShekylCtReadOutputOcFn =
    unsafe extern "C" fn(ctx: *mut c_void, pos: u64, o_out: *mut u8, c_out: *mut u8) -> bool;

struct CallbackStore {
    ctx: *mut c_void,
    read_leaf: ShekylCtReadLeafFn,
    read_layer_hash: ShekylCtReadLayerHashFn,
    read_output_oc: ShekylCtReadOutputOcFn,
}

impl PathStore for CallbackStore {
    fn leaf(&self, pos: u64) -> Result<[u8; LEAF_BYTES], PathAssembleError> {
        let mut buf = [0u8; LEAF_BYTES];
        let ok = unsafe { (self.read_leaf)(self.ctx, pos, buf.as_mut_ptr()) };
        if ok {
            Ok(buf)
        } else {
            Err(PathAssembleError::MissingLeaf(pos))
        }
    }

    fn layer_hash(&self, layer: u8, chunk: u64) -> Result<[u8; 32], PathAssembleError> {
        let mut buf = [0u8; 32];
        let ok = unsafe { (self.read_layer_hash)(self.ctx, layer, chunk, buf.as_mut_ptr()) };
        if ok {
            Ok(buf)
        } else {
            Err(PathAssembleError::MissingLayerHash { layer, chunk })
        }
    }

    fn output_oc(&self, pos: u64) -> Result<([u8; 32], [u8; 32]), PathAssembleError> {
        let mut o = [0u8; 32];
        let mut c = [0u8; 32];
        let ok = unsafe { (self.read_output_oc)(self.ctx, pos, o.as_mut_ptr(), c.as_mut_ptr()) };
        if ok {
            Ok((o, c))
        } else {
            Err(PathAssembleError::MissingOutputKey(pos))
        }
    }
}

fn write_err(error_out: *mut ShekylBuffer, err: &PathAssembleError) {
    if !error_out.is_null() {
        unsafe {
            *error_out = ShekylBuffer::from_vec(err.to_string().into_bytes());
        }
    }
}

/// Assemble the `get_curve_tree_path` blobs for one output.
///
/// `depth` is the caller's snapshot — the same value published as
/// `tree_depth`. On success `path_out` / `chunk_outputs_out` are Rust-owned
/// buffers the caller frees with `shekyl_buffer_free`. On failure `error_out`
/// names the store position.
///
/// # Safety
/// Out-pointers must be valid. Callbacks must write the documented byte
/// counts when they return true. `store_ctx` is only dereferenced by the
/// callbacks.
#[no_mangle]
pub unsafe extern "C" fn shekyl_assemble_curve_tree_path(
    output_idx: u64,
    ref_leaf_count: u64,
    tip_leaf_count: u64,
    depth: u8,
    store_ctx: *mut c_void,
    read_leaf: Option<ShekylCtReadLeafFn>,
    read_layer_hash: Option<ShekylCtReadLayerHashFn>,
    read_output_oc: Option<ShekylCtReadOutputOcFn>,
    path_out: *mut ShekylBuffer,
    chunk_outputs_out: *mut ShekylBuffer,
    error_out: *mut ShekylBuffer,
) -> bool {
    let null_bufs = || {
        if !path_out.is_null() {
            unsafe {
                *path_out = ShekylBuffer::null();
            }
        }
        if !chunk_outputs_out.is_null() {
            unsafe {
                *chunk_outputs_out = ShekylBuffer::null();
            }
        }
        if !error_out.is_null() {
            unsafe {
                *error_out = ShekylBuffer::null();
            }
        }
    };

    if path_out.is_null() || chunk_outputs_out.is_null() || error_out.is_null() {
        null_bufs();
        return false;
    }
    let (Some(read_leaf), Some(read_layer_hash), Some(read_output_oc)) =
        (read_leaf, read_layer_hash, read_output_oc)
    else {
        null_bufs();
        return false;
    };

    let store = CallbackStore {
        ctx: store_ctx,
        read_leaf,
        read_layer_hash,
        read_output_oc,
    };

    match assemble_rpc_path(&store, output_idx, ref_leaf_count, tip_leaf_count, depth) {
        Ok(bytes) => {
            unsafe {
                *path_out = ShekylBuffer::from_vec(bytes.path);
                *chunk_outputs_out = ShekylBuffer::from_vec(bytes.chunk_outputs);
                *error_out = ShekylBuffer::null();
            }
            true
        }
        Err(err) => {
            unsafe {
                *path_out = ShekylBuffer::null();
                *chunk_outputs_out = ShekylBuffer::null();
            }
            write_err(error_out, &err);
            false
        }
    }
}
