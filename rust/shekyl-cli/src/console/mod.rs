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

use shekyl_rpc_client::{wire, RpcMethod};
use shekyl_rpc_types::hash::HashHex;
use shekyl_rpc_types::kinds::{Height, NoParams};
use shekyl_rpc_types::wire::block::{BlockHeader, BlockSelect, BlockShowSelect};
use shekyl_rpc_types::wire::shared::{Selector, Slot, SlotState};

use crate::daemon::{DaemonClient, DaemonError};

mod alt_chain;
mod blockchain;
mod info;
mod node;
mod operator;
mod status;
#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::{daemon_status_reply, route_server_recording};

use alt_chain::alt_chain_info;
use blockchain::{print_blockchain_dynamic_stats, print_blockchain_info};
use status::show_status;

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

/// `print_block_header`'s text, field for field and in its order.
///
/// Built as lines and joined: writing to a `String` cannot fail, so
/// `write!` here would only produce `Result`s to discard.
fn render_block_header(h: &BlockHeader) -> String {
    let pow_hash = h.pow.0.map_or_else(String::new, |p| p.to_string());
    let time = h.time.0;
    [
        format!("timestamp: {time} ({})", human_readable_timestamp(time)),
        format!("previous hash: {}", h.parent),
        format!("nonce: {}", h.nonce.0),
        // The C++ streamed a bool, which prints as 0/1.
        format!("is orphan: {}", u8::from(h.orphan)),
        format!("height: {}", h.height.0),
        format!("depth: {}", h.depth.0),
        format!("hash: {}", h.hash),
        format!("difficulty: {}", h.difficulty.get()),
        format!("cumulative difficulty: {}", h.difficulty_cumulative.get()),
        // Empty when it was not asked for or not allowed — the C++ printed
        // the empty string just the same.
        format!("POW hash: {pow_hash}"),
        format!("block weight: {}", h.weight.0),
        // `null` off the main chain, which has none.
        format!(
            "long term weight: {}",
            h.weight_longterm
                .0
                .map_or_else(|| "none".to_owned(), |w| w.0.to_string())
        ),
        format!("num txes: {}", h.tx_count.0),
        format!("reward: {}", h.reward.to_atomic_units().to_skl_string()),
        format!("miner tx hash: {}", h.coinbase),
    ]
    .join("\n")
}

/// `block show`: one block's header, by hash or by height, with its
/// proof-of-work hash filled (the operator's own terminal; IG-Q56).
fn print_block(daemon: &DaemonClient, block: &crate::resolve::BlockRef) -> Result<String, String> {
    let select = match block {
        crate::resolve::BlockRef::Hash(hash) => {
            Selector::Hash(HashHex::from_hex(hash).map_err(|error| error.to_string())?)
        }
        crate::resolve::BlockRef::Height(height) => Selector::Height(Height(*height)),
    };
    let reply = call::<wire::BlockShow>(
        daemon,
        &BlockShowSelect(BlockSelect {
            select,
            pow: true,
            prune: Some(true),
        }),
    )?;
    Ok(render_block_header(&reply.header))
}

/// One call of method `M`, the console's way: the client's handshake runs
/// first, and an error is the operator's line. The `version` word does not
/// come through here: it reads `version` itself, and a daemon the
/// handshake would refuse is still one whose version it reports.
pub(super) fn call<M: RpcMethod>(
    daemon: &DaemonClient,
    request: &M::Request,
) -> Result<M::Reply, String> {
    daemon.call::<M>(request).map_err(|error| error.to_string())
}

/// `chain height`: the chain's block count, as this word has always
/// printed it — the tip's height plus one.
fn print_height(src: &DaemonClient) -> Result<String, String> {
    let tip = call::<wire::ChainHeight>(src, &NoParams)?;
    Ok(tip.height.0.saturating_add(1).to_string())
}

/// `print_transaction <hash> [+meta] [+hex]` — RK-4c. Reads
/// `tx_list` and nothing else, which is why it migrates with it
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
    let id = HashHex::from_hex(hash).map_err(|error| error.to_string())?;
    // The full form: the whole body, or `archived` with the shard it went
    // in when this daemon discarded its archival good (`PDM-Q10`).
    let reply = match daemon.call::<wire::TxList>(&wire::tx::TxListQuery {
        id: vec![id],
        prune: false,
    }) {
        Ok(reply) => reply,
        Err(error) => return Err(error.to_string()),
    };
    let [slot] = reply.as_slice() else {
        return Err(format!(
            "tx show: asked about 1 transaction, got {} slots",
            reply.len()
        ));
    };
    let tx = match slot {
        Slot::State(SlotState::Missing(_)) => return Ok(TxAnswer::NotHeld),
        // The chain does not hold it and the pool could not be asked.
        Slot::Unasked => {
            return Ok(TxAnswer::Narrative(format!(
                "Transaction {hash} is not in the chain, and the daemon's pool is unavailable \
                 until it restarts: whether the pool holds it is not known"
            )))
        }
        Slot::State(SlotState::Archived(archived)) => {
            return Ok(TxAnswer::Narrative(format!(
                "Transaction {hash} is in the chain, and its body is archived: this daemon \
                 discarded it with shard {}. Ask for it with prune, or from an archiver that \
                 serves that shard",
                archived.shard.0
            )))
        }
        Slot::Item(tx) => tx,
    };
    // A count is not a binding. The daemon is untrusted here, so the entry
    // must be the one that was asked for: the label first, which names the
    // cheap failure, then the body itself.
    if tx.id != id {
        return Err(format!("tx show: asked about {hash}, got {}", tx.id));
    }

    // The label check says the daemon *claims* this entry answers the
    // request; it does not make it so — every field of the reply is the
    // daemon's to choose, and the remote arm posts wherever the operator
    // pointed it. So the body is bound the way the wallet's `bind_served`
    // binds its own: parse the bytes and recompute the identity. The full
    // form carries the whole body, so it rehashes whole; a pruned segment
    // answering the full form does not parse whole and is refused here.
    let blob = tx.body.0.clone();
    let parsed = shekyl_wire::Transaction::from_bytes(&blob)
        .map_err(|_| format!("tx show: the daemon's body for {hash} is not a whole transaction"))?;
    let derived_hex = hex::encode(parsed.hash());
    if !derived_hex.eq_ignore_ascii_case(hash) {
        return Err(format!(
            "tx show: the entry is labeled {hash} but its body hashes to {derived_hex} — a \
             label is not an identity"
        ));
    }

    let mut out = Vec::new();
    match (tx.pooled, tx.mined_height.0, tx.mined_time.0) {
        (true, _, _) => out.push("Found in pool".to_owned()),
        (false, Some(height), Some(time)) => {
            out.push(format!("Found in blockchain at height {}", height.0));
            out.push(format!(
                "Block timestamp: {} ({})",
                time.0,
                human_readable_timestamp(time.0)
            ));
        }
        (false, _, _) => {
            return Err(format!(
                "tx show: the daemon says {hash} is mined and names no block for it"
            ))
        }
    }
    // The parse is the binding's, above — a body that did not parse (or
    // did not hash to the request) never reached this rendering.
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

/// `chain spent <key_image>`: where the key image is spent, if anywhere.
fn is_key_image_spent(src: &DaemonClient, ki: &str) -> Result<String, String> {
    let key_image = HashHex::from_hex(ki).map_err(|error| error.to_string())?;
    let reply = call::<wire::ChainSpent>(
        src,
        &wire::chain::SpentQuery {
            key_image: vec![key_image],
        },
    )?;
    // Exactly one, not "at least one": the request carries one key image, the
    // reply is positional, and a reply of a different length is unreadable
    // rather than partially readable.
    let [status] = reply.as_slice() else {
        return Err(format!(
            "chain spent: asked about 1 key image, got {} states",
            reply.len()
        ));
    };
    Ok(format!(
        "{ki}: {}",
        match status {
            wire::chain::Spent::Unspent => "unspent",
            wire::chain::Spent::Chain => "spent",
            wire::chain::Spent::Txpool => "spent (in pool)",
        }
    ))
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

/// What the console asks `peer_list` for: the whole peerlist, endpoints not
/// dialable on the public internet included. Named rather than written
/// twice, so `peer list` and `peer stats` cannot drift apart — the two
/// reporting different lists would read as a peerlist that changed between
/// two adjacent commands. The operator asking for the peer list is the one
/// person who wants every entry.
const LOCAL_TOO: bool = true;

/// What the console prints for a daemon started offline: the state,
/// not an empty table (Rick, 2026-10-14).
const OFFLINE_LINE: &str = "P2P: offline";

/// The code a daemon started offline refuses its P2P reads with.
const P2P_OFFLINE: &str = "p2p.offline";

/// One P2P read: the reply, or `None` for a daemon started offline (its
/// `p2p.offline` refusal is the state, not an error).
fn p2p_call<M: RpcMethod>(
    src: &DaemonClient,
    request: &M::Request,
) -> Result<Option<M::Reply>, String> {
    match src.call::<M>(request) {
        Ok(reply) => Ok(Some(reply)),
        Err(DaemonError::Refusal(refusal)) if refusal.diagnostic.code == P2P_OFFLINE => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

/// `None` for a daemon started offline.
fn fetch_peer_list(src: &DaemonClient) -> Result<Option<Vec<wire::p2p::PeerEntry>>, String> {
    p2p_call::<wire::PeerList>(src, &wire::p2p::PeerListQuery { local: LOCAL_TOO })
}

/// One line per peer: the list and the endpoint. No "last seen" column: the
/// Rust peer lists carry no clock (3.51).
fn render_peer(prefix: &str, peer: &wire::p2p::PeerEntry) -> String {
    format!("{prefix:<10} {}", peer.endpoint.0)
}

/// `peer list [white|gray] [limit]`.
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
    let Some(peers) = fetch_peer_list(src)? else {
        return Ok(OFFLINE_LINE.to_owned());
    };
    let mut out = Vec::new();
    let mut take = |prefix: &str, tier: wire::p2p::Tier| {
        for peer in peers
            .iter()
            .filter(|peer| peer.tier == tier)
            .take(if limit == 0 { usize::MAX } else { limit })
        {
            out.push(render_peer(prefix, peer));
        }
    };
    if white {
        take("white", wire::p2p::Tier::White);
    }
    if gray {
        take("gray", wire::p2p::Tier::Gray);
    }
    Ok(out.join("\n"))
}

/// `peer stats`: how full each list is.
#[deny(clippy::arithmetic_side_effects)]
fn print_peer_list_stats(src: &DaemonClient) -> Result<String, String> {
    let Some(peers) = fetch_peer_list(src)? else {
        return Ok(OFFLINE_LINE.to_owned());
    };
    let count = |tier| peers.iter().filter(|peer| peer.tier == tier).count();
    Ok(render_peer_list_stats(
        count(wire::p2p::Tier::White),
        count(wire::p2p::Tier::Gray),
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

/// `peer connections`. The rates are bytes per second, as the wire carries
/// them.
#[deny(clippy::arithmetic_side_effects)]
fn print_connections(src: &DaemonClient) -> Result<String, String> {
    let Some(connections) = p2p_call::<wire::PeerConnections>(src, &NoParams)? else {
        return Ok(OFFLINE_LINE.to_owned());
    };
    // Wide enough for the widest endpoint actually present, plus the four
    // characters of the `INC `/`OUT ` prefix and a two-column gutter.
    let width = connections
        .iter()
        .map(|c| c.endpoint.0.len().saturating_add(6))
        .max()
        .unwrap_or(0)
        .max(21);
    let mut out = vec![format!(
        "{:<width$}{:<10}{:<30}{:<20}{:<10}{:<12}{:<14}{:<10}{}",
        "Remote Host",
        "Connector",
        "Recv/Sent (inactive,sec)",
        "Mode",
        "Age(sec)",
        "Down (B/s)",
        "Down(now)",
        "Up (B/s)",
        "Up(now)"
    )];
    for c in &connections {
        let direction = if c.inbound { "INC " } else { "OUT " };
        out.push(format!(
            "{:<width$}{:<10}{:<30}{:<20}{:<10}{:<12}{:<14}{:<10}{:<8}{}",
            format!("{direction}{}", c.endpoint.0),
            match c.connector {
                wire::p2p::Connector::Clearnet => "clearnet",
                wire::p2p::Connector::Tor => "tor",
            },
            format!(
                "{}({})/{}({})",
                c.download.0, c.download_idle.0, c.upload.0, c.upload_idle.0
            ),
            c.mode.0.map_or("-", sync_mode_word),
            c.age.0,
            c.download_speed_average.0,
            c.download_speed_current.0,
            c.upload_speed_average.0,
            c.upload_speed_current.0,
            if c.local { "[LOCAL]" } else { "" },
        ));
    }
    Ok(out.join("\n"))
}

/// A sync mode as the wire spells it.
fn sync_mode_word(mode: wire::p2p::SyncMode) -> &'static str {
    use wire::p2p::SyncMode as M;
    match mode {
        M::Idle => "idle",
        M::Reachable => "reachable",
        M::Slot => "slot",
        M::Challenging => "challenging",
        M::PastCap => "past-cap",
        M::EvidenceCandidate => "evidence-candidate",
        M::Evidence => "evidence",
    }
}

/// The two rate rows `p2p stats` reads, from `option_show`
/// (`RPC_CHANNEL.md` §6.4): the download and the upload bound in bytes per
/// second, `None` for `unlimited`. The text is the grammar's, read through
/// the row's own kind, so a reply that is not a rate is named rather than
/// read as zero.
fn rate_limits(src: &DaemonClient) -> Result<(Option<u64>, Option<u64>), String> {
    const DOWN: &str = "p2p-download-max";
    const UP: &str = "p2p-upload-max";
    let reply = call::<wire::OptionShow>(
        src,
        &wire::node::OptionShow {
            name: Some(vec![
                shekyl_rpc_types::kinds::Text(DOWN.to_owned()),
                shekyl_rpc_types::kinds::Text(UP.to_owned()),
            ]),
        },
    )?;
    let bound = |name: &str| -> Result<Option<u64>, String> {
        let row = reply
            .iter()
            .find(|row| operator::row_name(row) == name)
            .ok_or_else(|| format!("option_show did not answer {name}"))?;
        let wire::node::OptionRow::Value(row) = row else {
            return Err(format!("option_show gave {name} as a secret"));
        };
        let text = row
            .value
            .0
            .as_ref()
            .map(|text| text.0.as_str())
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
    let Some(stats) = p2p_call::<wire::P2pStats>(src, &NoParams)? else {
        return Ok(OFFLINE_LINE.to_owned());
    };
    let (down, up) = rate_limits(src)?;
    let seconds = now.saturating_sub(stats.started.0);
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
        line("Received", stats.download.0, stats.download_packets.0, down),
        line("Sent", stats.upload.0, stats.upload_packets.0, up)
    ))
}

/// `sync status`: chain sync's view. Heights are block counts, as this
/// word has always printed them: the wire's tips plus one.
#[deny(clippy::arithmetic_side_effects)]
fn sync_info(src: &DaemonClient) -> Result<String, String> {
    let Some(reply) = p2p_call::<wire::SyncStatus>(src, &NoParams)? else {
        return Ok(OFFLINE_LINE.to_owned());
    };
    let height = reply.height.0.saturating_add(1);
    // A target below our own height (we are ahead of what we were told to
    // reach) reads as our height, so the percentage cannot exceed 100 or
    // divide by zero.
    let target = reply.target_height.0.saturating_add(1).max(height).max(1);
    #[expect(
        clippy::cast_precision_loss,
        reason = "a percentage for a human, from two heights"
    )]
    let progress = (height as f64 / target as f64) * 100.0;
    let mut out = vec![format!(
        "Height: {height}, target: {target} ({}%), {}{}",
        trimmed(progress, 4),
        sync_state_word(reply.state),
        if reply.stalled {
            ", stalled: no peer serves what this node still needs"
        } else {
            ""
        }
    )];
    out.push(format!("{} peers", reply.session.len()));
    out.push(
        "Remote Host               Mode                Claimed  Rate B/s  Headers  Bodies"
            .to_owned(),
    );
    for p in &reply.session {
        // Every accumulation saturates: each count is peer-influenced.
        let blocks = p
            .span
            .iter()
            .fold(0u64, |acc, span| acc.saturating_add(span.blocks.0));
        out.push(format!(
            "{:<24}  {:<18}  {:>7}  {:>8}  {:<7}  {}",
            p.endpoint.0,
            sync_mode_word(p.mode),
            // The claim is a tip; printed as the count it implies, as the
            // height above is.
            p.height
                .0
                .map_or_else(|| "-".to_owned(), |tip| tip.0.saturating_add(1).to_string()),
            p.download_speed
                .0
                .map_or_else(|| "-".to_owned(), |rate| rate.0.to_string()),
            if p.header.0.is_some() { "asked" } else { "-" },
            if p.span.is_empty() {
                "-".to_owned()
            } else {
                format!("{blocks} blocks in {} spans", p.span.len())
            },
        ));
    }
    Ok(out.join("\n"))
}

/// Chain sync's state as the wire spells it.
fn sync_state_word(state: wire::p2p::SyncState) -> &'static str {
    use wire::p2p::SyncState as S;
    match state {
        S::Unpeered => "unpeered",
        S::Behind => "behind",
        S::Following => "following",
        S::Synced => "synced",
    }
}
