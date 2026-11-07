// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Init, hashing, and secure memory.

use std::os::raw::c_char;
use std::sync::Mutex;

use super::legacy_types::*;
use super::legacy_util::*;

static CONSENSUS_REGISTRY: Mutex<Option<shekyl_consensus::ConsensusRegistry>> = Mutex::new(None);

// ─── Version / Init ─────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn shekyl_rust_version() -> *const c_char {
    static VERSION: &[u8] = b"2.0.0\0";
    VERSION.as_ptr() as *const c_char
}

/// Initialize the Rust subsystem. Registers built-in consensus modules.
#[no_mangle]
pub extern "C" fn shekyl_rust_init() -> bool {
    let mut registry = shekyl_consensus::ConsensusRegistry::new();
    let randomx = shekyl_consensus::RandomXProof::new(120, 720);
    if registry.register(Box::new(randomx)).is_err() {
        return false;
    }
    if let Ok(mut guard) = CONSENSUS_REGISTRY.lock() {
        *guard = Some(registry);
    }
    true
}

/// Get the name of the active consensus module. Returns null-terminated C string.
#[no_mangle]
pub extern "C" fn shekyl_active_consensus_module() -> *const c_char {
    static RANDOMX: &[u8] = b"RandomX\0";
    static NONE: &[u8] = b"none\0";
    if let Ok(guard) = CONSENSUS_REGISTRY.lock() {
        if let Some(ref reg) = *guard {
            if reg.active().is_some() {
                return RANDOMX.as_ptr() as *const c_char;
            }
        }
    }
    NONE.as_ptr() as *const c_char
}

// ─── Crypto: Hash Functions ──────────────────────────────────────────────────

/// Compute original Keccak-256 of `data_len` bytes at `data_ptr`.
/// Result is written to `out_ptr` which must point to 32 writable bytes.
/// Returns true on success, false if pointers are null.
///
/// **ABI name** `shekyl_cn_fast_hash` is stable (C++ callers via
/// `src/shekyl/shekyl_ffi.h`). Body forwards to
/// [`shekyl_crypto_hash::keccak256`] — same primitive, Rust-side name that
/// states it is Keccak-256 (not cSHAKE).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_cn_fast_hash(
    data_ptr: *const u8,
    data_len: usize,
    out_ptr: *mut u8,
) -> bool {
    if out_ptr.is_null() {
        return false;
    }
    let Some(data) = (unsafe { slice_from_ptr(data_ptr, data_len) }) else {
        return false;
    };
    let hash = shekyl_crypto_hash::keccak256(data);
    std::ptr::copy_nonoverlapping(hash.as_ptr(), out_ptr, 32);
    true
}

/// Compute Merkle tree root hash from an array of 32-byte hashes.
/// `hashes_ptr` points to `count * 32` contiguous bytes.
/// Result is written to `out_ptr` (32 bytes).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_tree_hash(
    hashes_ptr: *const u8,
    count: usize,
    out_ptr: *mut u8,
) -> bool {
    if out_ptr.is_null() || (count > 0 && hashes_ptr.is_null()) {
        return false;
    }
    let hashes: Vec<shekyl_crypto_hash::Hash> = if count == 0 {
        vec![]
    } else {
        let Some(byte_len) = count.checked_mul(32) else {
            return false;
        };
        let raw = std::slice::from_raw_parts(hashes_ptr, byte_len);
        raw.chunks_exact(32)
            .map(|c| {
                let mut h = [0u8; 32];
                h.copy_from_slice(c);
                h
            })
            .collect()
    };
    let root = shekyl_crypto_hash::tree_hash(&hashes);
    std::ptr::copy_nonoverlapping(root.as_ptr(), out_ptr, 32);
    true
}

// ─── SSL Certificate Generation ─────────────────────────────────────────────

/// Generate a self-signed ECDSA P-256 TLS certificate.
///
/// Writes PEM-encoded private key to `key_pem_out` and PEM-encoded certificate
/// to `cert_pem_out`. Caller owns both buffers and must free them with
/// `shekyl_buffer_free`. Certificate validity follows rcgen defaults (~1 year).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_generate_ssl_certificate(
    key_pem_out: *mut ShekylBuffer,
    cert_pem_out: *mut ShekylBuffer,
) -> bool {
    if key_pem_out.is_null() || cert_pem_out.is_null() {
        return false;
    }

    let Ok(key_pair) = rcgen::KeyPair::generate() else {
        return false;
    };

    let Ok(cert) = rcgen::CertificateParams::default().self_signed(&key_pair) else {
        return false;
    };

    let key_pem_str = key_pair.serialize_pem();
    let cert_pem_str = cert.pem();

    *key_pem_out = ShekylBuffer::from_vec(key_pem_str.into_bytes());
    *cert_pem_out = ShekylBuffer::from_vec(cert_pem_str.into_bytes());
    true
}

// ─── Secure Memory ──────────────────────────────────────────────────────────

/// Securely wipe memory at `ptr` for `len` bytes.
///
/// Uses `zeroize` to guarantee the write is not optimized away.
/// C signature: `void shekyl_memwipe(void *ptr, size_t len)`
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_memwipe(ptr: *mut libc::c_void, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    use zeroize::Zeroize;
    std::slice::from_raw_parts_mut(ptr as *mut u8, len).zeroize();
}

/// Lock memory pages containing `[ptr, ptr+len)` into RAM.
///
/// Returns 0 on success, -1 on failure (mirrors POSIX mlock).
/// C signature: `int shekyl_mlock(const void *ptr, size_t len)`
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_mlock(ptr: *const libc::c_void, len: usize) -> i32 {
    if ptr.is_null() || len == 0 {
        return -1;
    }
    #[cfg(unix)]
    {
        libc::mlock(ptr, len)
    }
    #[cfg(windows)]
    {
        extern "system" {
            fn VirtualLock(lpAddress: *const libc::c_void, dwSize: usize) -> i32;
        }
        let ret = VirtualLock(ptr, len);
        if ret != 0 {
            0
        } else {
            -1
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        -1
    }
}

/// Unlock previously locked memory pages.
///
/// Returns 0 on success, -1 on failure (mirrors POSIX munlock).
/// C signature: `int shekyl_munlock(const void *ptr, size_t len)`
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_munlock(ptr: *const libc::c_void, len: usize) -> i32 {
    if ptr.is_null() || len == 0 {
        return -1;
    }
    #[cfg(unix)]
    {
        libc::munlock(ptr, len)
    }
    #[cfg(windows)]
    {
        extern "system" {
            fn VirtualUnlock(lpAddress: *const libc::c_void, dwSize: usize) -> i32;
        }
        let ret = VirtualUnlock(ptr, len);
        if ret != 0 {
            0
        } else {
            -1
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        -1
    }
}

/// Advise the kernel to exclude `[ptr, ptr+len)` from core dumps.
///
/// Uses `madvise(MADV_DONTDUMP)` on Linux. No-op on other platforms.
/// Returns 0 on success, -1 on failure.
/// C signature: `int shekyl_madvise_dontdump(const void *ptr, size_t len)`
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_madvise_dontdump(ptr: *const libc::c_void, len: usize) -> i32 {
    if ptr.is_null() || len == 0 {
        return -1;
    }
    #[cfg(target_os = "linux")]
    {
        libc::madvise(ptr.cast_mut(), len, libc::MADV_DONTDUMP)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (ptr, len);
        0
    }
}

/// Return the system page size in bytes.
///
/// Returns 0 on failure.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_page_size() -> usize {
    #[cfg(unix)]
    {
        let ret = libc::sysconf(libc::_SC_PAGESIZE);
        if ret <= 0 {
            0
        } else {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                ret as usize
            }
        }
    }
    #[cfg(windows)]
    {
        #[repr(C)]
        struct SystemInfo {
            _pad: [u8; 4],
            page_size: u32,
            _rest: [u8; 52],
        }
        extern "system" {
            fn GetSystemInfo(info: *mut SystemInfo);
        }
        let mut info = SystemInfo {
            _pad: [0; 4],
            page_size: 0,
            _rest: [0; 52],
        };
        GetSystemInfo(&mut info);
        info.page_size as usize
    }
    #[cfg(not(any(unix, windows)))]
    {
        0
    }
}
