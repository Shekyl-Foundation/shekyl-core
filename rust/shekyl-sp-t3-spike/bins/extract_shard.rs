// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! D4 — extract a **real** archival shard from a live regtest chain.
//!
//! ```text
//! SHEKYL_SPIKE_RPC=http://127.0.0.1:28601 \
//! SHEKYL_SPIKE_SHARD_OUT=/path/to/shard.bin \
//! SHEKYL_SPIKE_SHARD_ID=0 \
//!   cargo run -p shekyl-sp-t3-spike --release --bin extract-shard
//! ```
//!
//! # The path, and why it is one batched call rather than 684
//!
//! `COMMAND_RPC_GET_CURVE_TREE_PATH` takes a **vector** of `output_indices` and
//! answers with one `path_entry` per index, each carrying a `chunk_outputs_blob`
//! of `[O:32][I:32][C:32][h_pqc:32]` for every leaf in that index's leaf-chunk
//! (`core_rpc_server_commands_defs.h`). A segment is `SEGMENT_LEAF_COUNT /
//! SELENE_CHUNK_WIDTH = 25 992 / 38 = 684` chunks, so asking for one index per
//! chunk covers the whole segment — and because the request is batched, that is a
//! handful of RPC calls, not 684 round-trips.
//!
//! # The blob is not the leaf, and the difference matters
//!
//! `chunk_outputs_blob` carries compressed **Ed25519 points**; a curve-tree leaf
//! is `shekyl_fcmp::tree::construct_leaf`'s `O.x ‖ I.x ‖ C.x ‖ h_pqc`, where the
//! first three fields are Wei25519 x-coordinates (Selene scalars), *not* the
//! compressed points. Serving the blob verbatim would serve 3.33 MB of real chain
//! data that is nonetheless **not what a persona archives**, so the conversion is
//! done here with the same function the wallet path uses
//! (`shekyl_curve_tree::recon::try_build_leaf` calls it too).
//!
//! Note the blob's `I` field is skipped rather than used: `construct_leaf`
//! re-derives `I = Hp(O)` itself, and taking it from the wire instead would make
//! the fixture depend on the daemon agreeing with the local derivation — a
//! difference that should surface as a mismatch, not be papered over.

use std::io::Write as _;

/// Leaves per frozen level-2 segment.
const SEGMENT_LEAF_COUNT: u64 = 25_992;
/// The same count as a `usize`, for buffer sizing without a lossy cast.
const SEGMENT_LEAF_COUNT_USIZE: usize = 25_992;
/// Leaf-chunk width (`SELENE_CHUNK_WIDTH`).
const CHUNK_WIDTH: u64 = 38;
/// Indices per RPC call — bounded so one request stays a reasonable size.
const BATCH: usize = 64;

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Pull `"chunk_outputs_blob"` values out of the JSON reply.
///
/// A hand-rolled scan rather than a JSON dependency: the spike is disposable and
/// this reads exactly one well-known field from a reply produced by our own
/// daemon. A malformed reply yields fewer chunks than requested, which the caller
/// treats as a hard failure rather than a short fixture.
fn extract_blobs(body: &str) -> Vec<Vec<u8>> {
    const KEY: &str = "\"chunk_outputs_blob\":\"";
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find(KEY) {
        rest = &rest[start + KEY.len()..];
        let Some(end) = rest.find('"') else { break };
        if let Some(bytes) = hex_decode(&rest[..end]) {
            out.push(bytes);
        }
        rest = &rest[end..];
    }
    out
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc = env("SHEKYL_SPIKE_RPC").ok_or("SHEKYL_SPIKE_RPC must be set (daemon base URL)")?;
    let out_path =
        env("SHEKYL_SPIKE_SHARD_OUT").ok_or("SHEKYL_SPIKE_SHARD_OUT must name the fixture file")?;
    let shard_id: u64 = env("SHEKYL_SPIKE_SHARD_ID")
        .unwrap_or_else(|| "0".to_owned())
        .parse()?;

    let base = shard_id * SEGMENT_LEAF_COUNT;
    // One index per leaf-chunk covers the segment; the daemon returns the whole
    // chunk for each.
    let indices: Vec<u64> = (0..SEGMENT_LEAF_COUNT / CHUNK_WIDTH)
        .map(|c| base + c * CHUNK_WIDTH)
        .collect();
    eprintln!(
        "extracting shard {shard_id}: leaves [{base}, {}) via {} chunk requests",
        base + SEGMENT_LEAF_COUNT,
        indices.len()
    );

    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(600)))
        .build()
        .new_agent();

    let mut leaves: Vec<[u8; 128]> = Vec::with_capacity(SEGMENT_LEAF_COUNT_USIZE);
    for (batch_no, batch) in indices.chunks(BATCH).enumerate() {
        let list = batch
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let req = format!(
            r#"{{"jsonrpc":"2.0","id":"0","method":"get_curve_tree_path","params":{{"output_indices":[{list}]}}}}"#
        );
        let body = agent
            .post(&format!("{rpc}/json_rpc"))
            .content_type("application/json")
            .send(req.as_bytes())?
            .into_body()
            .read_to_string()?;
        let blobs = extract_blobs(&body);
        if blobs.len() != batch.len() {
            return Err(format!(
                "batch {batch_no}: asked for {} chunks, got {} — the chain is not deep enough, \
                 or the reply was malformed. Extraction must not produce a short fixture.",
                batch.len(),
                blobs.len()
            )
            .into());
        }
        for blob in blobs {
            if !blob.len().is_multiple_of(128) {
                return Err(
                    format!("chunk blob is {} bytes, not a multiple of 128", blob.len()).into(),
                );
            }
            for entry in blob.chunks_exact(128) {
                let mut o = [0u8; 32];
                let mut c = [0u8; 32];
                let mut h = [0u8; 32];
                o.copy_from_slice(&entry[0..32]);
                // entry[32..64] is `I`; `construct_leaf` re-derives it (see the
                // module doc) so it is deliberately not read here.
                c.copy_from_slice(&entry[64..96]);
                h.copy_from_slice(&entry[96..128]);
                let leaf = shekyl_fcmp::tree::construct_leaf(&o, &c, &h)
                    .ok_or("construct_leaf refused an on-chain output")?;
                leaves.push(leaf);
            }
        }
        eprintln!(
            "  {}/{} chunks, {} leaves",
            (batch_no + 1) * BATCH.min(batch.len()),
            indices.len(),
            leaves.len()
        );
    }

    leaves.truncate(SEGMENT_LEAF_COUNT_USIZE);
    if leaves.len() != SEGMENT_LEAF_COUNT_USIZE {
        return Err(format!(
            "extracted {} leaves, need {SEGMENT_LEAF_COUNT}",
            leaves.len()
        )
        .into());
    }

    let mut f = std::fs::File::create(&out_path)?;
    for leaf in &leaves {
        f.write_all(leaf)?;
    }
    f.flush()?;
    eprintln!("wrote {} bytes to {out_path}", leaves.len() * 128);
    Ok(())
}
