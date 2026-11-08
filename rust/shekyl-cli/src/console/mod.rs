// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Console rendering for the daemon's words (`INPUT_GRAMMAR.md` §13, R8).
//!
//! The interactive C++ console and `shekyld <command>` both rendered here.
//! R8 keeps the remote arm: `shekyl-cli` posts through
//! [`shekyl_rpc_transport::SyncDaemon`] and renders the typed reply. The
//! in-process arm is gone with the console.

use shekyl_rpc_types::{GetHeightResponse, RestErrorEnvelope};
use shekyl_units::AtomicUnits;

use crate::daemon::DaemonClient;

mod alt_chain;
mod blockchain;
mod info;
mod node;
mod operator;
mod status;
#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::route_server_recording;

use alt_chain::alt_chain_info;
use blockchain::{print_blockchain_dynamic_stats, print_blockchain_info};
use status::show_status;

/// Decode a REST reply body: a JSON-RPC refusal first (a grant or a method
/// refusal has no `status`), then the success type, then the daemon's
/// status envelope, else a malformed-reply error. The refusal's class and
/// diagnostic are what the operator reads, never "missing field `status`".
fn decode_reply<T: serde::de::DeserializeOwned>(body: &[u8], method: &str) -> Result<T, String> {
    if let Some(refusal) = shekyl_rpc_types::errors::read_refusal(body) {
        return Err(refusal.report());
    }
    if let Ok(reply) = serde_json::from_slice::<T>(body) {
        return Ok(reply);
    }
    if let Ok(envelope) = serde_json::from_slice::<RestErrorEnvelope>(body) {
        return Err(format!("{method} failed: {}", envelope.error));
    }
    Err(format!(
        "malformed {method} reply: {}",
        String::from_utf8_lossy(body)
            .chars()
            .take(120)
            .collect::<String>()
    ))
}

/// `%Y-%m-%d %H:%M:%S` in UTC, or `<unknown>` below the same cutoff the C++
/// used (`tools::get_human_readable_timestamp`). The cutoff is 2009-02-13,
/// which predates any Shekyl block by years; it is kept so a corrupt or
/// zero timestamp reads as unknown rather than as 1970.
fn human_readable_timestamp(ts: u64) -> String {
    const UNKNOWN_BEFORE: u64 = 1_234_567_890;
    if ts < UNKNOWN_BEFORE {
        return "<unknown>".to_owned();
    }
    // Civil-from-days (Howard Hinnant's algorithm): no dependency, no libc
    // `gmtime`, and total for every value a u64 timestamp can hold.
    let days = i64::try_from(ts / 86_400).unwrap_or(i64::MAX);
    let secs_of_day = ts % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{year:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// The `0x`-prefixed wide difficulty rendered as decimal, which is what the
/// C++ console printed by constructing a `difficulty_type` from it.
fn wide_difficulty_decimal(wide: &str) -> String {
    let digits = wide.strip_prefix("0x").unwrap_or(wide);
    match u128::from_str_radix(digits, 16) {
        Ok(value) => value.to_string(),
        // The daemon produced this field; if it is ever unreadable, showing
        // it verbatim beats showing nothing.
        Err(_) => wide.to_owned(),
    }
}

/// `print_block_header`'s text, field for field and in its order.
///
/// Built as lines and joined: writing to a `String` cannot fail, so
/// `write!` here would only produce `Result`s to discard.
fn render_block_header(h: &shekyl_rpc_types::BlockHeader) -> String {
    let pow_hash = h.pow_hash.map_or_else(String::new, |p| p.to_string());
    [
        format!(
            "timestamp: {} ({})",
            h.timestamp,
            human_readable_timestamp(h.timestamp)
        ),
        format!("previous hash: {}", h.prev_hash),
        format!("nonce: {}", h.nonce),
        // The C++ streamed a bool, which prints as 0/1.
        format!("is orphan: {}", u8::from(h.orphan_status)),
        format!("height: {}", h.height),
        format!("depth: {}", h.depth),
        format!("hash: {}", h.hash),
        format!(
            "difficulty: {}",
            wide_difficulty_decimal(&h.wide_difficulty)
        ),
        format!(
            "cumulative difficulty: {}",
            wide_difficulty_decimal(&h.wide_cumulative_difficulty)
        ),
        // Empty when it was not asked for or not allowed — the C++ printed
        // the empty string just the same.
        format!("POW hash: {pow_hash}"),
        format!("block size: {}", h.block_size),
        format!("block weight: {}", h.block_weight),
        format!("long term weight: {}", h.long_term_weight),
        format!("num txes: {}", h.num_txes),
        format!(
            "reward: {}",
            AtomicUnits::from_raw(h.reward).to_skl_string()
        ),
        format!("miner tx hash: {}", h.miner_tx_hash),
    ]
    .join("\n")
}

/// `print_block_by_hash` / `print_block_by_height`: the two console commands
/// that read `get_block` and nothing else, which is why they migrate with it
/// (the design's console matrix, §2.1).
fn print_block(daemon: &DaemonClient, block: &crate::resolve::BlockRef) -> Result<String, String> {
    let mut request = shekyl_rpc_types::GetBlockRequest {
        fill_pow_hash: true,
        ..Default::default()
    };
    match block {
        crate::resolve::BlockRef::Hash(hash) => request.hash = hash.clone(),
        crate::resolve::BlockRef::Height(height) => request.height = *height,
    }

    // In-process the console is the operator's own terminal, so the
    // restricted-listener rule does not apply: the C++ passed
    // `fill_pow_hash` straight through here too.
    let reply: shekyl_rpc_types::GetBlockResponse = native_json_rpc(daemon, "get_block", &request)?;
    require_ok(&reply.status)?;

    // The C++ order: the blob (only with `+hex`) and a blank line, then the
    // header, then the block's json.
    let mut out = String::new();
    out.push_str(&render_block_header(&reply.block_header));
    out.push('\n');
    if let Some(json) = &reply.json {
        out.push_str(json);
    }
    Ok(out)
}

/// One JSON-RPC call. `method` is a lookup in the method table; the posted
/// name is the table's, and a missing row is an error.
///
/// The client's handshake runs first. `version` does not come through here:
/// it reads `get_version` itself, and a daemon the handshake would refuse is
/// still one whose version it reports.
pub(super) fn native_json_rpc<Req, Res>(
    daemon: &DaemonClient,
    method: &str,
    request: &Req,
) -> Result<Res, String>
where
    Req: serde::Serialize,
    Res: serde::de::DeserializeOwned,
{
    let method = crate::daemon::posted_json(method).map_err(|error| error.to_string())?;
    daemon
        .json_rpc(method, request)
        .map_err(|error| error.to_string())
}

/// One REST post. `path` is a lookup in the method table. The handshake
/// runs first.
pub(super) fn rest_post(
    daemon: &DaemonClient,
    path: &str,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let path = crate::daemon::posted_rest(path).map_err(|error| error.to_string())?;
    daemon.post(path, body).map_err(|error| error.to_string())
}

fn require_ok(status: &shekyl_rpc_types::RpcStatus) -> Result<(), String> {
    if status.is_ok() {
        Ok(())
    } else {
        Err(status.0.clone())
    }
}

/// The wide difficulty as a number, or `None` if the daemon sent something
/// unreadable.
///
/// [`wide_difficulty_decimal`] is this plus a fallback to the raw string;
/// the two exist apart because summing needs the number and rendering needs
/// something to print either way.
fn wide_difficulty_value(wide: &str) -> Option<u128> {
    u128::from_str_radix(wide.strip_prefix("0x").unwrap_or(wide), 16).ok()
}

fn print_height(src: &DaemonClient) -> Result<String, String> {
    let body = rest_post(src, "/get_height", b"{}".to_vec())?;
    let reply = decode_reply::<GetHeightResponse>(&body, "get_height")?;
    if !reply.status.is_ok() {
        return Err(reply.status.0);
    }
    Ok(reply.height.to_string())
}

/// `print_transaction <hash> [+meta] [+hex]` — RK-4c. Reads
/// `get_transactions` and nothing else, which is why it migrates with it
/// (§2.1). Its `+json` went with epee's rendering (IG-Q55; `tx show`'s
/// `--json` is the session's).
/// What the daemon said about one transaction.
///
/// [`TxAnswer::NotHeld`] is the only miss. An archived body and an
/// unavailable pool are narratives about an id the daemon does hold.
/// [`TxAnswer::Held`] carries the text and the raw body; base64 is applied
/// when the line is printed.
pub(crate) enum TxAnswer {
    /// The daemon answered, and the id is not among the transactions it holds.
    NotHeld,
    /// A sentence the daemon does hold: the body is archived, or the pool
    /// cannot be read.
    Narrative(String),
    /// The rendering, and the body bytes the binding already checked.
    Held { text: String, body: Vec<u8> },
}

/// The daemon's view of `hash`. A transport failure, an identity refusal,
/// or a body that does not hash to `hash` is `Err`.
pub(crate) fn transaction(daemon: &DaemonClient, hash: &str) -> Result<TxAnswer, String> {
    // The full form: the whole body, or `archived` with the shard it went
    // in when this daemon discarded its archival good (`PDM-Q10`).
    let request = shekyl_rpc_types::GetTransactionsRequest {
        txs_hashes: vec![hash.to_owned()],
        prune: false,
    };
    let reply = fetch_transactions(daemon, &request)?;
    if !reply.status.is_ok() {
        return Err(reply.status.0);
    }
    // One requested hash lands in exactly one of these lists. A missed id
    // is not held even when another list also names it. An archived id has
    // no entry, so an empty `txs` is a miss only after archived and
    // unavailable have been read. Extra entries are a malformed reply.
    // A count is not a binding. The daemon is untrusted here, so the entry
    // must be the one that was asked for: `parse_tx_batch` holds the wallet's
    // consumers to the same rule, and a console that printed whatever came
    // back would answer a question the operator did not ask.
    if !reply.missed_tx.is_empty() {
        return Ok(TxAnswer::NotHeld);
    }
    if !reply.unavailable_tx.is_empty() {
        return Ok(TxAnswer::Narrative(format!(
            "Transaction {hash} is not in the chain, and the daemon's pool is unavailable \
             until it restarts: whether the pool holds it is not known"
        )));
    }
    if let [archived] = reply.archived.as_slice() {
        return Ok(TxAnswer::Narrative(format!(
            "Transaction {hash} is in the chain, and its body is archived: this daemon \
             discarded it with shard {}. Ask for it with prune, or from an archiver that \
             serves that shard",
            archived.shard
        )));
    }
    if reply.txs.is_empty() {
        return Ok(TxAnswer::NotHeld);
    }
    let [tx] = reply.txs.as_slice() else {
        return Err(format!(
            "print_transaction: asked about 1 transaction, got {}",
            reply.txs.len()
        ));
    };
    if !tx.tx_hash.to_string().eq_ignore_ascii_case(hash) {
        return Err(format!(
            "print_transaction: asked about {hash}, got {}",
            tx.tx_hash
        ));
    }

    // The label check above says the daemon *claims* this entry answers the
    // request; it does not make it so — every field of the reply is the
    // daemon's to choose, and the remote arm posts wherever the operator
    // pointed it. So the body is bound the way `parse_tx_batch` binds the
    // wallet's: parse the bytes and recompute the identity. The full form
    // carries the whole body, so it rehashes whole; a reply that answers the
    // full form with a pruned segment is refused here, not reassembled.
    if tx.as_hex.is_empty() {
        return Err(format!(
            "print_transaction: the daemon answered {hash} in the pruned form to a request \
             for the whole body"
        ));
    }
    let blob = hex::decode(&tx.as_hex)
        .map_err(|_| format!("print_transaction: the daemon's body for {hash} is not hex"))?;
    let parsed = shekyl_wire::Transaction::from_bytes(&blob).map_err(|_| {
        format!("print_transaction: the daemon's body for {hash} is not a transaction")
    })?;
    let derived_hex = hex::encode(parsed.hash());
    if !derived_hex.eq_ignore_ascii_case(hash) {
        return Err(format!(
            "print_transaction: the entry is labeled {hash} but its body hashes \
             to {derived_hex} — a label is not an identity"
        ));
    }

    let mut out = Vec::new();
    match &tx.location {
        shekyl_rpc_types::TxLocation::Pooled { .. } => out.push("Found in pool".to_owned()),
        shekyl_rpc_types::TxLocation::Mined { block_height, .. } => {
            out.push(format!("Found in blockchain at height {block_height}"));
        }
    }

    // Size, weight and the block time are part of the rendering. `+meta`
    // was the console's flag for them; §13's `tx show` has no such flag.
    if let shekyl_rpc_types::TxLocation::Mined {
        block_timestamp, ..
    } = &tx.location
    {
        out.push(format!(
            "Block timestamp: {block_timestamp} ({})",
            human_readable_timestamp(*block_timestamp)
        ));
    }
    // The parse is the binding's, above — a body that did not parse (or
    // did not hash to the request) never reached this rendering, so the
    // old "Error parsing transaction" soft lines have no input left.
    out.push(format!("Size: {}", blob.len()));
    out.push(format!("Weight: {}", parsed.weight()));
    Ok(TxAnswer::Held {
        text: out.join("\n"),
        body: blob,
    })
}

/// The line the console prints. Base64 is applied here, once, when the
/// operator asked for the bytes. A narrative is that line; a miss is the
/// "wasn't found" sentence.
pub(crate) fn render_transaction(
    answer: TxAnswer,
    hash: &str,
    want_body: bool,
) -> Result<String, String> {
    match answer {
        TxAnswer::NotHeld => Err(format!("Transaction wasn't found: {hash}")),
        TxAnswer::Held { text, body } if want_body => Ok(format!("{text}\n{}", encode_body(&body))),
        TxAnswer::Narrative(text) | TxAnswer::Held { text, .. } => Ok(text),
    }
}

/// The serialized body, as the shell prints it: base64, RFC 4648 §4, padded.
pub(crate) fn encode_body(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `is_key_image_spent <key_image>` — RK-4c. Reads that method only.
fn is_key_image_spent(src: &DaemonClient, ki: &str) -> Result<String, String> {
    let request = shekyl_rpc_types::IsKeyImageSpentRequest {
        key_images: vec![ki.to_owned()],
    };
    let body = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    let raw = rest_post(src, "/is_key_image_spent", body)?;
    // A handler's failure is a `RestErrorEnvelope`. Decoding success-only
    // would report "malformed" over the reason the server gave.
    let reply =
        decode_reply::<shekyl_rpc_types::IsKeyImageSpentResponse>(&raw, "is_key_image_spent")?;
    if !reply.status.is_ok() {
        return Err(reply.status.0);
    }
    // Exactly one, not "at least one": the request carries one key image, the
    // reply is positional, and a reply of a different length is unreadable
    // rather than partially readable — the property the type's own doc names.
    let [status] = reply.spent_status.as_slice() else {
        return Err(format!(
            "is_key_image_spent: asked about 1 key image, got {} statuses",
            reply.spent_status.len()
        ));
    };
    Ok(format!(
        "{ki}: {}",
        match status {
            shekyl_rpc_types::KeyImageStatus::Unspent => "unspent",
            shekyl_rpc_types::KeyImageStatus::SpentInBlockchain => "spent",
            shekyl_rpc_types::KeyImageStatus::SpentInPool => "spent (in pool)",
        }
    ))
}

/// The `get_transactions` fetch, shared by the console commands that need it.
///
/// The live arm calls the facts path and the projection **directly**, as
/// `print_block` does — not `json_endpoint`, which dispatches through the C++
/// JSON table this slice empties. Naming a route by string there would have
/// compiled and then answered "no reply" the moment the route left C++, which
/// is exactly what it did until Copilot caught it on this PR. Calling the
/// Rust functions makes that class of breakage a compile error.
///
/// The console is the operator's own node, so the pool read is unrestricted —
/// the same answer the C++ gave a null `ctx` (§7, 2026-08-26).
fn fetch_transactions(
    src: &DaemonClient,
    request: &shekyl_rpc_types::GetTransactionsRequest,
) -> Result<shekyl_rpc_types::GetTransactionsResponse, String> {
    let body = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    let raw = rest_post(src, "/get_transactions", body)?;
    decode_reply::<shekyl_rpc_types::GetTransactionsResponse>(&raw, "get_transactions")
}

/// Run one already-parsed daemon word.
///
/// `now` is read once so a command's whole output describes one instant.
/// The daemon's software version, the same text `version` prints for it.
pub(crate) fn daemon_software_version(daemon: &DaemonClient) -> Result<String, String> {
    node::version(daemon)
}

pub(crate) fn execute(
    daemon: &DaemonClient,
    view: &crate::resolve::View,
) -> Result<String, String> {
    let now = unix_now();
    match view {
        crate::resolve::View::ChainHeight => print_height(daemon),
        crate::resolve::View::ChainDifficulty => node::show_difficulty(daemon),
        crate::resolve::View::ChainStats { last } => print_blockchain_dynamic_stats(daemon, *last),
        crate::resolve::View::ChainAlt => alt_chain_info(daemon),
        crate::resolve::View::ChainSpent { hash } => is_key_image_spent(daemon, hash),
        crate::resolve::View::BlockShow(block) => print_block(daemon, block),
        crate::resolve::View::BlockHeaderList { from, to } => {
            print_blockchain_info(daemon, *from, *to)
        }
        crate::resolve::View::PeerList { white, gray, max } => {
            let limit = max.map_or(0, |n| usize::try_from(n).unwrap_or(usize::MAX));
            print_peer_list(daemon, *white, *gray, limit)
        }
        crate::resolve::View::PeerStats => print_peer_list_stats(daemon),
        crate::resolve::View::PeerConnections => print_connections(daemon),
        crate::resolve::View::P2pStats => print_net_stats(daemon, now),
        crate::resolve::View::SyncStatus => sync_info(daemon),
        crate::resolve::View::DaemonStatus => show_status(daemon, now),
        crate::resolve::View::TxpoolStats => node::print_transaction_pool_stats(daemon),
        crate::resolve::View::ChainCoinbaseSum { from, to } => {
            operator::chain_coinbase_sum(daemon, *from, *to)
        }
        crate::resolve::View::TxRelay { hash } => operator::tx_relay(daemon, hash),
        crate::resolve::View::TxpoolList { short } => operator::txpool_list(daemon, *short),
        crate::resolve::View::TxpoolFlush { id } => operator::txpool_flush(daemon, id.as_deref()),
        crate::resolve::View::BanList => operator::ban_list(daemon),
        crate::resolve::View::BanAdd { ip, duration } => operator::ban_add(daemon, ip, *duration),
        crate::resolve::View::BanRemove { ip } => operator::ban_remove(daemon, ip),
        crate::resolve::View::BanShow { ip } => operator::ban_show(daemon, ip),
        crate::resolve::View::OptionSet { name, value } => {
            operator::option_set(daemon, name, value)
        }
        crate::resolve::View::OptionShow { name } => operator::option_show(daemon, name.as_deref()),
        crate::resolve::View::DaemonStop => operator::daemon_stop(daemon),
    }
}

/// Unix seconds, read once per console command so a whole rendering
/// describes one instant.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ── RK-5a: the p2p console commands ─────────────────────────────────────────
//
// Five commands, four methods. Console output is not a wire contract, so the
// layouts below are rationalized rather than transcribed — but every *value*
// is the value the C++ printed, and the pinned tests are on values.
//
// Two things the C++ layout got wrong that are not reproduced.
// `print_connections` computed a `host_field_width` from the widest address
// and then wrote `setw(30)` anyway, so the computation had no effect; and it
// composed the address column as `ip + ":" + port`, which for a tor peer —
// where both are empty by construction — printed `OUT :`. The address column
// here uses `address`, which is populated for every arm.

/// Format a float for a human: fixed precision, then trailing zeros and a
/// bare trailing dot removed.
///
/// Rust's `{}` on an `f64` prints the shortest string that round-trips, which
/// is exactly the wrong property for a display — `7.0 / 1000.0 * 100.0`
/// renders `0.7000000000000001`. The C++ printed through an ostream at its
/// six-significant-digit default; this is not that, and does not try to be
/// (console output is not a wire contract). What it is is bounded: the noise
/// cannot reach the operator, and a value that is exactly round still reads
/// round.
fn trimmed(value: f64, decimals: usize) -> String {
    let s = format!("{value:.decimals$}");
    match s.find('.') {
        Some(_) => s.trim_end_matches('0').trim_end_matches('.').to_owned(),
        None => s,
    }
}

/// `tools::get_human_readable_bytes`: base-2 units, `B` with no decimals and
/// every larger unit with two.
fn human_readable_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    #[expect(
        clippy::cast_precision_loss,
        reason = "a display string; the C++ casts to double here too"
    )]
    let value = bytes as f64;
    if bytes < 1024 {
        return format!("{value:.0} B");
    }
    for (limit, unit, divisor) in [
        (1024u64 * 1024, "kB", KIB),
        (1024 * 1024 * 1024, "MB", KIB * KIB),
        (1024 * 1024 * 1024 * 1024, "GB", KIB * KIB * KIB),
    ] {
        if bytes < limit {
            return format!("{:.2} {unit}", value / divisor);
        }
    }
    format!("{:.2} TB", value / (KIB * KIB * KIB * KIB))
}

/// `tools::get_human_readable_timespan`: seconds below a minute, otherwise
/// one decimal place in the largest unit that fits.
fn human_readable_timespan(seconds: u64) -> String {
    #[expect(
        clippy::cast_precision_loss,
        reason = "a display string; the C++ casts to float here too"
    )]
    let s = seconds as f64;
    const MINUTE: f64 = 60.0;
    const HOUR: f64 = 3600.0;
    const DAY: f64 = 3600.0 * 24.0;
    // The C++ uses 30.5 days for a month and 365.25 for a year, and the
    // boundaries are the same expressions — so the unit a value falls into is
    // decided by the same arithmetic that then divides it.
    const MONTH: f64 = DAY * 30.5;
    const YEAR: f64 = DAY * 365.25;
    if s < MINUTE {
        return format!("{seconds} seconds");
    }
    for (limit, divisor, unit) in [
        (HOUR, MINUTE, "minutes"),
        (DAY, HOUR, "hours"),
        (MONTH, DAY, "days"),
        (YEAR, MONTH, "months"),
        (YEAR * 100.0, YEAR, "years"),
    ] {
        if s < limit {
            return format!("{:.1} {unit}", s / divisor);
        }
    }
    "a long time".to_owned()
}

/// What the console passes for `public_only`: the whole peerlist. Named
/// rather than written twice as a bare `false`, so the two commands cannot
/// drift apart — `print_pl` and `print_pl_stats` reporting different lists
/// would read as a peerlist that changed between two adjacent commands.
const PUBLIC_ONLY: bool = false;

/// The peerlist as the console asks for it.
///
/// Blocked peers included, because the operator asking for the peer list is
/// the one person who wants to see them — and **the whole list, not the
/// public part of it**, which is what both C++ callers asked for. That is
/// worth spelling out because the wire default is the opposite and reading
/// the struct suggests otherwise: `public_only` is `KV_SERIALIZE_OPT(…,
/// true)`, but an `OPT` default is applied when *deserializing* a document
/// that omits the field, and the console never deserialized one — it filled
/// an `epee::misc_utils::struct_init` request, which value-initializes, so
/// `public_only` was `false` on the in-process arm and serialized as an
/// explicit `false` on the RPC arm. `print_pl_stats` also wrote `= false`
/// outright. Asking for the public list here would silently drop the
/// non-public zones from `print_pl` and leave it disagreeing with the counts
/// `print_pl_stats` prints.
/// What the console prints for a daemon started offline: the state,
/// not an empty table (Rick, 2026-10-14).
const OFFLINE_LINE: &str = "P2P: offline";

/// `None` for a daemon started offline.
fn fetch_peer_list(
    src: &DaemonClient,
    public_only: bool,
) -> Result<Option<shekyl_rpc_types::GetPeerListResponse>, String> {
    let request = shekyl_rpc_types::GetPeerListRequest {
        public_only,
        include_blocked: true,
    };
    let body = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    let raw = rest_post(src, "/get_peer_list", body)?;
    let reply = decode_reply::<shekyl_rpc_types::P2pReply<shekyl_rpc_types::GetPeerListResponse>>(
        &raw,
        "get_peer_list",
    )?;
    let shekyl_rpc_types::P2pReply::Running(reply) = reply else {
        return Ok(None);
    };
    if !reply.status.is_ok() {
        return Err(reply.status.0);
    }
    Ok(Some(reply))
}

/// One line per peer: the list and the address. No "last seen" column: the
/// Rust peer lists carry no clock (3.51).
fn render_peer(prefix: &str, peer: &shekyl_rpc_types::Peer) -> String {
    // `host` means three different things across the address arms, and only
    // two of them leave a port to append. On Tor, `host` is
    // the whole `network_address::str()`, which *already ends in a port*, and
    // `port` is 0; the C++ appended anyway and printed
    // `abcdefghijklmnop.onion:18080:0`. An inherited rendering, not a
    // regression, and corrected here rather than carried (rule 16).
    let addr = if peer.port == 0 {
        peer.host.clone()
    } else {
        format!("{}:{}", peer.host, peer.port)
    };
    format!("{prefix:<10} {addr}")
}

/// `print_peer_list [white|gray] [limit]`.
///
/// `limit` applies **per list**, not to the pair, as the C++ did. The
/// `pruned` selector went with the stripe engine (`PDM-Q7`): there is no
/// per-peer pruning state left to filter on.
#[deny(clippy::arithmetic_side_effects)]
fn print_peer_list(
    src: &DaemonClient,
    white: bool,
    gray: bool,
    limit: usize,
) -> Result<String, String> {
    let Some(reply) = fetch_peer_list(src, PUBLIC_ONLY)? else {
        return Ok(OFFLINE_LINE.to_owned());
    };
    let mut out = Vec::new();
    let mut take = |prefix: &str, peers: &[shekyl_rpc_types::Peer]| {
        for peer in peers
            .iter()
            .take(if limit == 0 { usize::MAX } else { limit })
        {
            out.push(render_peer(prefix, peer));
        }
    };
    if white {
        take("white", &reply.white_list);
    }
    if gray {
        take("gray", &reply.gray_list);
    }
    Ok(out.join("\n"))
}

/// `print_pl_stats`: how full each list is.
#[deny(clippy::arithmetic_side_effects)]
fn print_peer_list_stats(src: &DaemonClient) -> Result<String, String> {
    let Some(reply) = fetch_peer_list(src, PUBLIC_ONLY)? else {
        return Ok(OFFLINE_LINE.to_owned());
    };
    Ok(render_peer_list_stats(
        reply.white_list.len(),
        reply.gray_list.len(),
        shekyl_peerlist::WHITE_CAP,
        shekyl_peerlist::GRAY_CAP,
    ))
}

/// The rendering, over values a caller states.
///
/// Split out so the capacities are a parameter: the lists' caps are
/// `shekyl-peerlist`'s constants, read in exactly one place, and this
/// function is tested against the values the daemon holds.
fn render_peer_list_stats(
    white: usize,
    gray: usize,
    white_limit: usize,
    gray_limit: usize,
) -> String {
    let line = |name: &str, size: usize, limit: usize| -> String {
        let percent = if limit == 0 {
            0.0
        } else {
            #[expect(
                clippy::cast_precision_loss,
                reason = "a percentage for a human, from two small counts"
            )]
            let fraction = size as f64 / limit as f64;
            fraction * 100.0
        };
        format!(
            "{name} list size: {size}/{limit} ({}%)",
            trimmed(percent, 4)
        )
    };
    format!(
        "{}\n{}",
        line("White", white, white_limit),
        line("Gray", gray, gray_limit)
    )
}

/// `print_connections`.
#[deny(clippy::arithmetic_side_effects)]
fn print_connections(src: &DaemonClient) -> Result<String, String> {
    let reply: shekyl_rpc_types::P2pReply<shekyl_rpc_types::GetConnectionsResponse> =
        native_json_rpc(src, "get_connections", &serde_json::json!({}))?;
    let shekyl_rpc_types::P2pReply::Running(reply) = reply else {
        return Ok(OFFLINE_LINE.to_owned());
    };
    require_ok(&reply.status)?;
    // Wide enough for the widest address actually present, plus the four
    // characters of the `INC `/`OUT ` prefix and a two-column gutter — the
    // computation the C++ did and then ignored in favour of a fixed `setw(30)`
    // that its own prefix could overrun.
    let width = reply
        .connections
        .iter()
        .map(|c| c.address.len().saturating_add(6))
        .max()
        .unwrap_or(0)
        .max(21);
    let mut out = vec![format!(
        "{:<width$}{:<8}{:<30}{:<18}{:<15}{:<12}{:<14}{:<10}{}",
        "Remote Host",
        "Type",
        "Recv/Sent (inactive,sec)",
        "State",
        "Livetime(sec)",
        "Down (kB/s)",
        "Down(now)",
        "Up (kB/s)",
        "Up(now)"
    )];
    for c in &reply.connections {
        let direction = if c.incoming { "INC " } else { "OUT " };
        let tail = format!(
            "{}{}",
            if c.localhost { "[LOCALHOST]" } else { "" },
            if c.local_ip { "[LAN]" } else { "" }
        );
        out.push(format!(
            "{:<width$}{:<8}{:<30}{:<18}{:<15}{:<12}{:<14}{:<10}{:<8}{tail}",
            format!("{direction}{}", c.address),
            address_type_name(c.address_type),
            format!(
                "{}({})/{}({})",
                c.recv_count, c.recv_idle_time, c.send_count, c.send_idle_time
            ),
            c.state.map_or("-", shekyl_rpc_types::SyncMode::as_str),
            c.live_time,
            c.avg_download,
            c.current_download,
            c.avg_upload,
            c.current_upload,
        ));
    }
    Ok(out.join("\n"))
}

/// `get_address_type_name`'s mapping, as the console printed it — including
/// its lower-case `invalid`, which is the only arm whose spelling differs
/// from the others. Carried verbatim; the C++ it came from is deleted, so
/// this is the definition now rather than a second copy of one.
fn address_type_name(address_type: u8) -> &'static str {
    match address_type {
        1 => "IPv4",
        2 => "IPv6",
        4 => "Tor",
        _ => "invalid",
    }
}

/// The two rate rows `print_net_stats` reads, from `option_show`
/// (`RPC_CHANNEL.md` §6.4: `/get_limit` was replaced, not ported): the
/// download and the upload bound in bytes per second, `None` for
/// `unlimited`. The text is the grammar's, built back through the row's own
/// constructor, so a reply that is not a rate is named rather than read as
/// zero.
fn rate_limits(src: &DaemonClient) -> Result<(Option<u64>, Option<u64>), String> {
    const DOWN: &str = "p2p-download-max";
    const UP: &str = "p2p-upload-max";
    let names = vec![DOWN.to_owned(), UP.to_owned()];
    let request = shekyl_rpc_types::options::OptionShowRequest {
        names: Some(names.clone()),
    };
    let reply: shekyl_rpc_types::options::OptionsResponse =
        native_json_rpc(src, "option_show", &request)?;
    let bound = |name: &str| -> Result<Option<u64>, String> {
        let row = reply
            .options
            .iter()
            .find(|r| r.name() == name)
            .ok_or_else(|| format!("option_show did not answer {name}"))?;
        let text = row
            .value()
            .flatten()
            .ok_or_else(|| format!("option_show gave {name} no value"))?;
        let kind = &shekyl_daemon_config::TABLE
            .row(name)
            .ok_or_else(|| format!("{name} is not a row of the table"))?
            .kind;
        match kind.parse_text(text) {
            Ok(shekyl_options::Value::Rate(bytes)) => Ok(Some(bytes)),
            Ok(shekyl_options::Value::Word(_)) => Ok(None),
            Ok(_) | Err(_) => Err(format!(
                "option_show gave {name} the text {text:?}, not a rate"
            )),
        }
    };
    Ok((bound(DOWN)?, bound(UP)?))
}

/// `print_net_stats`.
#[deny(clippy::arithmetic_side_effects)]
fn print_net_stats(src: &DaemonClient, now: u64) -> Result<String, String> {
    let raw = rest_post(src, "/get_net_stats", b"{}".to_vec())?;
    let stats = decode_reply::<shekyl_rpc_types::GetNetStatsResponse>(&raw, "get_net_stats")?;
    if !stats.status.is_ok() {
        return Err(stats.status.0);
    }
    let (down, up) = rate_limits(src)?;
    let seconds = now.saturating_sub(stats.start_time);
    let line = |verb: &str, bytes: u64, packets: u64, limit: Option<u64>| -> String {
        // Total by construction rather than guarded; see `methods::average_kib`.
        let average = bytes.checked_div(seconds).unwrap_or(0);
        let head = format!(
            "{verb} {bytes} bytes ({}) in {packets} packets in {}, average {}/s",
            human_readable_bytes(bytes),
            human_readable_timespan(seconds),
            human_readable_bytes(average),
        );
        match limit {
            None => format!("{head}, no limit"),
            Some(limit) => {
                #[expect(
                    clippy::cast_precision_loss,
                    reason = "a percentage for a human, from byte counts"
                )]
                let percent = if limit == 0 {
                    0.0
                } else {
                    average as f64 / limit as f64 * 100.0
                };
                format!(
                    "{head} = {percent:.2}% of the limit of {}/s",
                    human_readable_bytes(limit)
                )
            }
        }
    };
    Ok(format!(
        "{}\n{}",
        line(
            "Received",
            stats.total_bytes_in,
            stats.total_packets_in,
            down
        ),
        line("Sent", stats.total_bytes_out, stats.total_packets_out, up)
    ))
}

/// `sync_info`: chain sync's view (3.68).
#[deny(clippy::arithmetic_side_effects)]
fn sync_info(src: &DaemonClient) -> Result<String, String> {
    let reply: shekyl_rpc_types::P2pReply<shekyl_rpc_types::SyncInfoResponse> =
        native_json_rpc(src, "sync_info", &serde_json::json!({}))?;
    let shekyl_rpc_types::P2pReply::Running(reply) = reply else {
        return Ok(OFFLINE_LINE.to_owned());
    };
    require_ok(&reply.status)?;
    // A target below our own height (we are ahead of what we were told to
    // reach) reads as our height, so the percentage cannot exceed 100 or
    // divide by zero.
    let target = reply.target_height.max(reply.height).max(1);
    #[expect(
        clippy::cast_precision_loss,
        reason = "a percentage for a human, from two heights"
    )]
    let progress = (reply.height as f64 / target as f64) * 100.0;
    let mut out = vec![format!(
        "Height: {}, target: {target} ({}%), {}{}",
        reply.height,
        trimmed(progress, 4),
        reply.state.as_str(),
        if reply.stalled {
            ", stalled: no peer serves what this node still needs"
        } else {
            ""
        }
    )];
    out.push(format!("{} peers", reply.peers.len()));
    out.push(
        "Remote Host               Mode                Claimed  Rate B/s  Headers  Bodies"
            .to_owned(),
    );
    for p in &reply.peers {
        // Every accumulation saturates: each count is peer-influenced.
        let blocks = p
            .body_requests
            .iter()
            .fold(0u64, |acc, span| acc.saturating_add(span.count));
        out.push(format!(
            "{:<24}  {:<18}  {:>7}  {:>8}  {:<7}  {}",
            p.address,
            p.mode.as_str(),
            p.claimed_height
                .map_or_else(|| "-".to_owned(), |height| height.to_string()),
            p.rate
                .map_or_else(|| "-".to_owned(), |rate| rate.to_string()),
            if p.header_request.is_some() {
                "asked"
            } else {
                "-"
            },
            if p.body_requests.is_empty() {
                "-".to_owned()
            } else {
                format!("{blocks} blocks in {} spans", p.body_requests.len())
            },
        ));
    }
    Ok(out.join("\n"))
}
