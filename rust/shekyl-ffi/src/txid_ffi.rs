// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transaction id's FFI: `shekyl-wire` mixes, the C++ daemon serializes
//! and cuts (`ARCHIVAL_SHARD_COUNT_CUTOVER.md` `SHT-Q2`; rule 40).
//!
//! The txid binds the transaction's archival length, so two mixers would be
//! two measurements of a consensus operand, free to disagree about which
//! transaction — and which shard — an id names. There is one, in
//! [`shekyl_wire::TxidSegments::txid`], and `calculate_transaction_hash`
//! reaches it here.
//!
//! The daemon hands over **byte ranges, not a transaction**: the four regions
//! of the blob it just serialized, cut at the offsets its serializer recorded,
//! and the two facts about them that are not bytes. Nothing is parsed on this
//! side, which is what makes the call total — the daemon names a body before
//! it validates it (relay dedup, the `already known` arm), so an entry that
//! could refuse a malformed body would give that body no id where the C++
//! mixer gave it one. And nothing is measured on that side: there is no
//! length parameter, because a length the caller supplied is the second
//! measurement this cutover exists to remove.

use shekyl_wire::{prunable_hash_of, TxidSegments};

use crate::legacy_util::slice_from_ptr;

/// The consensus txid of the transaction whose serialization was cut into
/// these four ranges, written to `out_txid` (32 bytes).
///
/// `pqc_auths` is the tx-level segment as the body carries it — no count
/// prefix — and `pqc_auth_count` is how many authorizations it holds.
/// `first_input_is_spend` is whether the transaction has a first input that
/// is not `gen`. An empty range may be passed as a null pointer.
///
/// Returns `false`, writing nothing, only when a pointer cannot be the range
/// it claims: `out_txid` is null, or a range with a non-zero length is null
/// or longer than `isize::MAX` bytes (no allocation is). No content of the
/// ranges can make it fail.
///
/// # Safety
/// Each range's pointer is readable for its length; `out_txid` is writable
/// for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_txid_from_segments(
    prefix: *const u8,
    prefix_len: usize,
    ct_base: *const u8,
    ct_base_len: usize,
    pqc_auths: *const u8,
    pqc_auths_len: usize,
    pqc_auth_count: usize,
    first_input_is_spend: bool,
    prunable: *const u8,
    prunable_len: usize,
    out_txid: *mut u8,
) -> bool {
    if out_txid.is_null() {
        return false;
    }
    // SAFETY: each pointer is readable for its length (caller contract); the
    // helper maps a null pointer with a zero length to the empty slice.
    let (Some(prefix), Some(ct_base), Some(pqc_auths), Some(prunable)) = (unsafe {
        (
            slice_from_ptr(prefix, prefix_len),
            slice_from_ptr(ct_base, ct_base_len),
            slice_from_ptr(pqc_auths, pqc_auths_len),
            slice_from_ptr(prunable, prunable_len),
        )
    }) else {
        return false;
    };
    let txid = TxidSegments {
        prefix,
        ct_base,
        pqc_auths,
        pqc_auth_count,
        first_input_is_spend,
        prunable,
    }
    .txid();
    // SAFETY: `out_txid` is non-null and writable for 32 bytes (caller
    // contract).
    unsafe { core::ptr::copy_nonoverlapping(txid.as_bytes().as_ptr(), out_txid, 32) };
    true
}

/// The prunable digest of the transaction whose serialization's **prunable
/// range** is `prunable`, written to `out_hash` (32 bytes).
///
/// The sibling of [`shekyl_txid_from_segments`], for the one txid operand the
/// daemon also stores and serves on its own: the `txs_prunable_hash` row, and
/// `prunable_hash` beside a pruned body in `get_transactions`. A wallet mixes
/// that value into the txid it checks the body against, so it has to be the
/// function the mixer uses ([`shekyl_wire::prunable_hash_of`]) and not a
/// second one beside it.
///
/// One byte range and nothing else. The digest takes no archival length —
/// that operand is the mixer's, measured where the txid is mixed — and no
/// transaction is parsed, so no content can make the call fail. An empty
/// range — a body with no prunable region — is a valid input and may be
/// passed as a null pointer.
///
/// Returns `false`, writing nothing, only when a pointer cannot be the range
/// it claims: `out_hash` is null, or `prunable` has a non-zero length and is
/// null or longer than `isize::MAX` bytes (no allocation is).
///
/// # Safety
/// `prunable` is readable for `prunable_len` bytes; `out_hash` is writable
/// for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_tx_prunable_hash(
    prunable: *const u8,
    prunable_len: usize,
    out_hash: *mut u8,
) -> bool {
    if out_hash.is_null() {
        return false;
    }
    // SAFETY: `prunable` is readable for its length (caller contract); the
    // helper maps a null pointer with a zero length to the empty slice.
    let Some(prunable) = (unsafe { slice_from_ptr(prunable, prunable_len) }) else {
        return false;
    };
    let hash = prunable_hash_of(prunable);
    // SAFETY: `out_hash` is non-null and writable for 32 bytes (caller
    // contract).
    unsafe { core::ptr::copy_nonoverlapping(hash.as_bytes().as_ptr(), out_hash, 32) };
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use shekyl_wire::Transaction;

    /// A pinned transaction and the id `shekyl-wire` pins for it.
    struct Pinned {
        bytes: Vec<u8>,
        txid: [u8; 32],
    }

    fn pinned(fixture: &str) -> Pinned {
        let doc: Value = serde_json::from_str(fixture).expect("fixture json");
        let bytes = hex::decode(doc["tx_hex"].as_str().expect("tx_hex")).expect("hex");
        let mut txid = [0u8; 32];
        txid.copy_from_slice(
            &hex::decode(doc["tx_hash_hex"].as_str().expect("tx_hash_hex")).expect("hex"),
        );
        Pinned { bytes, txid }
    }

    /// Cut `bytes` the way the daemon's serializer does and call the export.
    fn txid_over_the_boundary(bytes: &[u8]) -> Option<[u8; 32]> {
        let tx = Transaction::from_bytes(bytes).expect("fixture parses");
        let segments = tx.write_segments().expect("segments");
        let prunable_at = bytes.len() - segments.prunable.len();
        let pqc_auths_at = prunable_at - segments.pqc_auths.len();
        // The prefix range is everything before the ct section.
        let mut ct_section = Vec::new();
        tx.ct
            .write(&mut ct_section)
            .expect("Vec write is infallible");
        assert!(bytes.ends_with(&ct_section), "the blob closes with it");
        let (prefix, ct_base) = bytes[..pqc_auths_at].split_at(bytes.len() - ct_section.len());
        let pqc_auths = &bytes[pqc_auths_at..prunable_at];
        let prunable = &bytes[prunable_at..];
        let first_input_is_spend = matches!(
            tx.prefix.inputs.first(),
            Some(first) if !matches!(first, shekyl_wire::Input::Gen(_))
        );
        let pqc_auth_count = match &tx.ct {
            shekyl_wire::Ct::Fcmp { pqc_auths, .. } => pqc_auths.len(),
            shekyl_wire::Ct::Null(_) => 0,
        };
        let mut out = [0u8; 32];
        // SAFETY: every range is a live slice; `out` is 32 writable bytes.
        let ok = unsafe {
            shekyl_txid_from_segments(
                prefix.as_ptr(),
                prefix.len(),
                ct_base.as_ptr(),
                ct_base.len(),
                pqc_auths.as_ptr(),
                pqc_auths.len(),
                pqc_auth_count,
                first_input_is_spend,
                prunable.as_ptr(),
                prunable.len(),
                out.as_mut_ptr(),
            )
        };
        ok.then_some(out)
    }

    /// The export reproduces the pinned ids of the two FCMP++ arities — the
    /// spend, with a `pqc_auths` component, and the serve-credit form,
    /// without — and of a coinbase, from the blob cut the way the daemon
    /// cuts it.
    #[test]
    fn reproduces_the_pinned_txids_from_the_daemons_cut() {
        let spend = pinned(include_str!(
            "../../shekyl-wire/tests/fixtures/pruned_tx_hash_parity_v1.json"
        ));
        let serve_credit = pinned(include_str!(
            "../../shekyl-wire/tests/fixtures/serve_credit_tx_parity_v1.json"
        ));
        for (what, pin) in [("spend", spend), ("serve-credit", serve_credit)] {
            assert_eq!(txid_over_the_boundary(&pin.bytes), Some(pin.txid), "{what}");
        }

        let block = shekyl_wire::Block::from_bytes(include_bytes!(
            "../../shekyl-wire/tests/vectors/regtest_coinbase_h1.block"
        ))
        .expect("block vector");
        let coinbase = block.miner_transaction.serialize();
        assert_eq!(
            txid_over_the_boundary(&coinbase),
            Some(block.miner_transaction.hash().to_bytes()),
            "coinbase"
        );
    }

    /// The only refusals are of a pointer that cannot be the range it
    /// claims, and they write nothing.
    #[test]
    fn refuses_only_a_range_that_cannot_be_read() {
        let bytes = [0u8; 4];
        let mut out = [0xEEu8; 32];
        // SAFETY: `bytes` and `out` are live; the null range claims 3 bytes,
        // which is the refusal under test and is never read.
        let null_range = unsafe {
            shekyl_txid_from_segments(
                bytes.as_ptr(),
                bytes.len(),
                core::ptr::null(),
                3,
                core::ptr::null(),
                0,
                0,
                false,
                core::ptr::null(),
                0,
                out.as_mut_ptr(),
            )
        };
        assert!(!null_range);
        assert_eq!(out, [0xEE; 32], "a refusal writes nothing");

        // SAFETY: `bytes` and `out` are live; the prunable range claims more
        // than `isize::MAX` bytes, which no allocation holds, so it is
        // refused before anything is read.
        let oversized_range = unsafe {
            shekyl_txid_from_segments(
                bytes.as_ptr(),
                bytes.len(),
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                0,
                false,
                bytes.as_ptr(),
                isize::MAX as usize + 1,
                out.as_mut_ptr(),
            )
        };
        assert!(!oversized_range);
        assert_eq!(out, [0xEE; 32], "a refusal writes nothing");

        // SAFETY: every range is empty; the null `out_txid` is the refusal
        // under test and is never written.
        let null_out = unsafe {
            shekyl_txid_from_segments(
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                0,
                false,
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
            )
        };
        assert!(!null_out);

        // SAFETY: every range is empty and `out` is 32 writable bytes.
        let all_empty = unsafe {
            shekyl_txid_from_segments(
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                0,
                false,
                core::ptr::null(),
                0,
                out.as_mut_ptr(),
            )
        };
        assert!(all_empty, "content cannot make it fail, even none at all");
    }

    /// The prunable export hashes the range it is given by the wire crate's
    /// one definition: the pinned spend's digest from its prunable tail, and
    /// `keccak256("")` for a body with no prunable region, passed as null.
    #[test]
    fn the_prunable_export_is_the_wire_crates_digest_of_the_range() {
        let doc: Value = serde_json::from_str(include_str!(
            "../../shekyl-wire/tests/fixtures/pruned_tx_hash_parity_v1.json"
        ))
        .expect("fixture json");
        let full = hex::decode(doc["tx_hex"].as_str().expect("tx_hex")).expect("hex");
        let pruned = hex::decode(doc["pruned_hex"].as_str().expect("pruned_hex")).expect("hex");
        let pinned = hex::decode(doc["prunable_hash_hex"].as_str().expect("digest")).expect("hex");
        let range = &full[pruned.len()..];

        let mut out = [0u8; 32];
        // SAFETY: `range` is a live slice; `out` is 32 writable bytes.
        assert!(unsafe { shekyl_tx_prunable_hash(range.as_ptr(), range.len(), out.as_mut_ptr()) });
        assert_eq!(out.as_slice(), pinned.as_slice());

        // SAFETY: an empty range may be null; `out` is 32 writable bytes.
        assert!(unsafe { shekyl_tx_prunable_hash(core::ptr::null(), 0, out.as_mut_ptr()) });
        assert_eq!(
            out,
            shekyl_wire::empty_region_prunable_hash().to_bytes(),
            "no prunable region is the digest of nothing, not the null hash"
        );
    }

    /// Its only refusals are of a pointer that cannot be the range it
    /// claims, and they write nothing.
    #[test]
    fn the_prunable_export_refuses_only_a_range_that_cannot_be_read() {
        let mut out = [0xEEu8; 32];
        // SAFETY: the null range claims 3 bytes, which is the refusal under
        // test and is never read; `out` is 32 writable bytes.
        assert!(!unsafe { shekyl_tx_prunable_hash(core::ptr::null(), 3, out.as_mut_ptr()) });
        assert_eq!(out, [0xEE; 32], "a refusal writes nothing");
        let bytes = [0u8; 4];
        // SAFETY: the length is past `isize::MAX`, which no allocation is, so
        // it is refused before anything is read; `out` is 32 writable bytes.
        assert!(!unsafe {
            shekyl_tx_prunable_hash(bytes.as_ptr(), isize::MAX as usize + 1, out.as_mut_ptr())
        });
        assert_eq!(out, [0xEE; 32], "a refusal writes nothing");
        // SAFETY: `bytes` is live; the null `out_hash` is the refusal under
        // test and is never written.
        assert!(!unsafe {
            shekyl_tx_prunable_hash(bytes.as_ptr(), bytes.len(), core::ptr::null_mut())
        });
    }
}
