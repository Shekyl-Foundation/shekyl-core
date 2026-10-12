// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The facts `get_info` reads, one read per unit of disclosure
//! (`docs/design/DAEMON_RPC_KV_GET_INFO.md` §4.2).
//!
//! `get_info` is gathered **by part** (RK-D24): a part the caller will not
//! be shown is not read. So [`InfoFacts`] is not one snapshot of everything
//! but six reads, and the handler makes only those its caller is entitled
//! to. A read that is never made cannot fail the caller it was never for.
//!
//! What a restricted (public) caller costs, exactly:
//!
//! - **Not read:** Status (start time, the volume's free space, the
//!   alt-block count, the two connection counts) and Peers (the socket
//!   counts and peerlist sizes).
//! - **Read, as for every caller:** the chain, the pool's broadcast count,
//!   and the board's session counts, which are behind Health's `has_peers`
//!   and are skipped only for an offline node.
//! - **Read, as a transitional exception:** the store's size on disk, one
//!   `stat` of the data file. A restricted reply still carries
//!   `database_size`, rounded, so the caller receives it and it is read
//!   for them. It joins the not-read set when a restricted reply stops
//!   carrying Status (RK-Q8).
//!
//! **This trait is the contract the store cutover inherits.** Today its one
//! implementation reads the C++ core through the facts shim. When the Rust
//! store replaces the C++ one, the implementation changes and this does
//! not — which is why the rules that matter are stated here, on the trait,
//! and tested against a double, rather than left to the C++ side to get
//! right. Two in particular:
//!
//! - [`InfoFacts::chain`] describes **one** chain state. Everything it
//!   returns that comes from the chain store is read under one lock and
//!   belongs to the tip it names (RK-D20).
//! - [`InfoFacts::store_size`] reports a size it could not read as
//!   [`FactsFault::StoreUnreadable`], never as `0` (RK-D23). The size is
//!   read on this side, by [`store_file_size`], for that reason.
//! - [`InfoFacts::sessions`] reports a p2p layer that is not up as
//!   [`FactsFault::HubAbsent`], never as zero sessions. It is read from
//!   the seam board, which is Rust's, without visiting C++, and it is
//!   **one** snapshot: `has_peers` and the two connection counts describe
//!   the same board.

use std::path::Path;
use std::sync::Arc;

use shekyl_economics::TxVolume;
use shekyl_rpc_types::DaemonNetwork;
use shekyl_types::{BlockHash, ChainCount};
use shekyl_units::AtomicUnits;

use crate::chain_facts::{decode_target_count, FactsFault};
use crate::core::CoreRpc;

/// The chain at its tip, with the node's own view of whether it is caught
/// up. Read for every caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoChainFacts {
    /// Chain **count**: the top block's height plus one.
    pub chain_height: ChainCount,
    pub top_hash: BlockHash,
    /// Difficulty of the next block.
    pub difficulty: u128,
    /// Cumulative difficulty at the tip.
    pub cumulative_difficulty: u128,
    /// The difficulty target, in seconds.
    pub difficulty_target: u64,
    /// Transactions on the chain, coinbases included.
    pub total_transactions: u64,
    pub block_weight_limit: u64,
    pub block_weight_median: u64,
    pub adjusted_time: u64,
    /// Gross coins emitted through the tip.
    pub already_generated_coins: AtomicUnits,
    pub total_burned: AtomicUnits,
    /// The trailing transaction-volume window ending at the tip.
    pub tx_volume: TxVolume,
    /// The core's target count, or `None` when it has none.
    pub core_target_height: Option<ChainCount>,
    /// The protocol's own predicate, read once.
    pub synchronized: bool,
    pub busy_syncing: bool,
    pub offline: bool,
    pub following_degraded: bool,
    pub nettype: DaemonNetwork,
    pub protocol_version: u64,
}

/// What describes this node. Read only for a caller who is shown Status.
///
/// The store's on-disk size is not here: it is read on this side, so that
/// a failure is a fault ([`InfoFacts::store_size`]). The connection counts
/// are not here either: they come from the board ([`InfoFacts::sessions`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoStatusFacts {
    pub start_time: u64,
    /// Free space on the data directory's volume.
    pub free_space: u64,
    pub alt_blocks_count: u64,
    /// The build's version string.
    pub version: String,
}

/// Per-connector transport and peerlist detail. Read only for a caller who
/// is shown Peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InfoPeersFacts {
    pub public_incoming_sockets: u64,
    pub public_outgoing_sockets: u64,
    pub tor_incoming_sockets: u64,
    pub tor_outgoing_sockets: u64,
    pub white_peerlist_size: u64,
    pub grey_peerlist_size: u64,
}

/// Which pool entries a count covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolScope {
    /// The broadcast set: what every caller may be told.
    Broadcast,
    /// Every entry, including those this node has not broadcast. Host-only
    /// data (`RPC_CHANNEL.md` §6.1, RT-O9.3).
    All,
}

/// The reads behind `get_info`.
pub trait InfoFacts: Send + Sync {
    /// The chain at its tip. One chain state: see the module docs.
    fn chain(&self) -> Result<InfoChainFacts, FactsFault>;
    /// The pool's population over `scope`.
    fn pool_count(&self, scope: PoolScope) -> Result<u64, FactsFault>;
    /// The chain store's size on disk, in bytes.
    ///
    /// # Errors
    ///
    /// [`FactsFault::StoreUnreadable`] when the size cannot be read. A size
    /// of `0` is an answer — an empty store — and is never returned for a
    /// store that could not be read.
    fn store_size(&self) -> Result<u64, FactsFault>;
    /// Status facts. Called only on behalf of a caller who is shown Status.
    fn status(&self) -> Result<InfoStatusFacts, FactsFault>;
    /// Peers facts. Called only on behalf of a caller who is shown Peers.
    fn peers(&self) -> Result<InfoPeersFacts, FactsFault>;
    /// The node's sessions, counted over one snapshot of the seam board.
    /// Read for every caller of an online node: `handshaken` is behind
    /// Health's `has_peers`, and Health is never withheld. Not read for a
    /// node that [`InfoChainFacts::offline`] says is offline, which binds no
    /// hub and has no sessions by configuration.
    ///
    /// The two directional counts are Status members. They come from this
    /// read and not from a second one so that a reply cannot say a node has
    /// peers and no connections, or the reverse.
    ///
    /// # Errors
    ///
    /// [`FactsFault::HubAbsent`] when the p2p hub is not up. Zero sessions
    /// is an answer — a node with nobody to talk to — and is never returned
    /// for a hub that is not there.
    fn sessions(&self) -> Result<SessionCounts, FactsFault>;
}

/// The node's p2p sessions, on every connector, from one board snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionCounts {
    /// Sessions this node opened, handshake finished or not. A dial in
    /// flight is a connection.
    pub outbound: u64,
    /// Sessions opened to this node, handshake finished or not.
    pub inbound: u64,
    /// Sessions in either direction that have finished the handshake. A
    /// session before its handshake cannot relay, which is what every
    /// reader of `has_peers` is asking (RK-Q4).
    pub handshaken: u64,
}

impl SessionCounts {
    /// No sessions: what an offline node has, by configuration.
    pub const NONE: Self = Self {
        outbound: 0,
        inbound: 0,
        handshaken: 0,
    };
}

/// The seam board's session counts.
///
/// # Errors
///
/// [`FactsFault::HubAbsent`] when no hub is bound; [`FactsFault::Unknown`]
/// for a code the export does not document.
pub fn sessions() -> Result<SessionCounts, FactsFault> {
    // Values no board can hold: if the export claimed success without
    // writing, the answer would not pass for small counts.
    let mut counts = crate::ffi::SeamSessionCountsFfi {
        outbound: u64::MAX,
        inbound: u64::MAX,
        established: u64::MAX,
    };
    // SAFETY: `counts` is a valid, writable struct of the export's layout.
    let code = unsafe { crate::ffi::shekyl_seam_session_counts(&raw mut counts) };
    sessions_from(code, counts)
}

/// What a return code of the board's count export means.
fn sessions_from(
    code: i32,
    counts: crate::ffi::SeamSessionCountsFfi,
) -> Result<SessionCounts, FactsFault> {
    match code {
        crate::ffi::SHEKYL_SEAM_COUNT_OK => Ok(SessionCounts {
            outbound: counts.outbound,
            inbound: counts.inbound,
            handshaken: counts.established,
        }),
        crate::ffi::SHEKYL_SEAM_COUNT_ERR_NO_HUB => Err(FactsFault::HubAbsent),
        other => Err(FactsFault::Unknown(other)),
    }
}

/// The size of the chain store's data file.
///
/// This is the whole of the size read, and it lives here so that it is the
/// same code whichever store names the file. A missing file, a file the
/// process may not stat, or a path that is not a file is
/// [`FactsFault::StoreUnreadable`].
pub fn store_file_size(path: &Path) -> Result<u64, FactsFault> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => Ok(meta.len()),
        Ok(_) => {
            tracing::error!(
                path = %path.display(),
                "the chain store's data file is not a file; its size cannot be read"
            );
            Err(FactsFault::StoreUnreadable)
        }
        Err(error) => {
            tracing::error!(
                path = %path.display(),
                %error,
                "the chain store's data file cannot be read for its size"
            );
            Err(FactsFault::StoreUnreadable)
        }
    }
}

/// Production [`InfoFacts`] over the live core handle.
pub struct FfiInfoFacts {
    core: Arc<CoreRpc>,
}

impl FfiInfoFacts {
    pub fn new(core: Arc<CoreRpc>) -> Self {
        Self { core }
    }
}

impl InfoFacts for FfiInfoFacts {
    fn chain(&self) -> Result<InfoChainFacts, FactsFault> {
        let pod = self.core.info_chain().map_err(FactsFault::from_code)?;
        // An unknown discriminant is a fault, never a default (VC-D14).
        let nettype =
            DaemonNetwork::from_cryptonote(pod.nettype).ok_or(FactsFault::Inconsistent)?;
        Ok(InfoChainFacts {
            chain_height: ChainCount::from_raw(pod.chain_height),
            top_hash: BlockHash::from_bytes(pod.top_hash),
            difficulty: u128::from(pod.difficulty_hi) << 64 | u128::from(pod.difficulty_lo),
            cumulative_difficulty: u128::from(pod.cumulative_difficulty_hi) << 64
                | u128::from(pod.cumulative_difficulty_lo),
            difficulty_target: pod.difficulty_target,
            total_transactions: pod.total_transactions,
            block_weight_limit: pod.block_weight_limit,
            block_weight_median: pod.block_weight_median,
            adjusted_time: pod.adjusted_time,
            already_generated_coins: AtomicUnits::from_raw(pod.already_generated_coins),
            total_burned: AtomicUnits::from_raw(pod.total_burned),
            tx_volume: TxVolume::window(pod.tx_volume_count_sum, pod.tx_volume_blocks),
            core_target_height: decode_target_count(pod.core_target_height),
            synchronized: pod.synchronized != 0,
            busy_syncing: pod.busy_syncing != 0,
            offline: pod.offline != 0,
            following_degraded: pod.following_degraded != 0,
            nettype,
            protocol_version: u64::from(pod.protocol_version),
        })
    }

    fn pool_count(&self, scope: PoolScope) -> Result<u64, FactsFault> {
        self.core
            .info_pool_count(scope == PoolScope::All)
            .map_err(FactsFault::from_code)
    }

    fn store_size(&self) -> Result<u64, FactsFault> {
        let path = self.core.info_store_file().map_err(FactsFault::from_code)?;
        store_file_size(&path)
    }

    fn status(&self) -> Result<InfoStatusFacts, FactsFault> {
        let (pod, version) = self.core.info_status().map_err(FactsFault::from_code)?;
        // The build always has a version. An empty one is a shim that did
        // not write it, and the reply type refuses it on the reading side;
        // it is a fault here and not a reply nobody could decode.
        if version.is_empty() {
            return Err(FactsFault::Inconsistent);
        }
        Ok(InfoStatusFacts {
            start_time: pod.start_time,
            free_space: pod.free_space,
            alt_blocks_count: pod.alt_blocks_count,
            version,
        })
    }

    fn peers(&self) -> Result<InfoPeersFacts, FactsFault> {
        let pod = self.core.info_peers().map_err(FactsFault::from_code)?;
        Ok(InfoPeersFacts {
            public_incoming_sockets: pod.public_incoming_sockets,
            public_outgoing_sockets: pod.public_outgoing_sockets,
            tor_incoming_sockets: pod.tor_incoming_sockets,
            tor_outgoing_sockets: pod.tor_outgoing_sockets,
            white_peerlist_size: pod.white_peerlist_size,
            grey_peerlist_size: pod.grey_peerlist_size,
        })
    }

    fn sessions(&self) -> Result<SessionCounts, FactsFault> {
        sessions()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A missing hub is a fault, and zero sessions is an answer.** The
    /// two are different return codes of the board's export and stay
    /// different here; a code the export does not document is not guessed
    /// at.
    #[test]
    fn a_missing_hub_is_a_fault_and_zero_sessions_is_an_answer() {
        use crate::ffi::{
            SeamSessionCountsFfi, SHEKYL_SEAM_COUNT_ERR_NO_HUB, SHEKYL_SEAM_COUNT_OK,
        };

        let pod = |outbound, inbound, established| SeamSessionCountsFfi {
            outbound,
            inbound,
            established,
        };
        assert_eq!(
            sessions_from(SHEKYL_SEAM_COUNT_OK, pod(0, 0, 0)),
            Ok(SessionCounts::NONE)
        );
        assert_eq!(
            sessions_from(SHEKYL_SEAM_COUNT_OK, pod(8, 12, 7)),
            Ok(SessionCounts {
                outbound: 8,
                inbound: 12,
                handshaken: 7,
            }),
            "each count lands in its own member"
        );
        assert_eq!(
            sessions_from(SHEKYL_SEAM_COUNT_ERR_NO_HUB, pod(0, 0, 0)),
            Err(FactsFault::HubAbsent),
            "no hub is not zero sessions, whatever the slots hold"
        );
        assert_eq!(
            sessions_from(-1, pod(0, 0, 0)),
            Err(FactsFault::Unknown(-1))
        );
        assert_eq!(sessions_from(1, pod(3, 3, 3)), Err(FactsFault::Unknown(1)));
    }

    /// The unit-test binary links no hub, and the stub that stands in for
    /// the export says so. The read through it is the fault, not zeros.
    #[test]
    fn the_read_with_no_hub_linked_is_the_fault() {
        assert_eq!(sessions(), Err(FactsFault::HubAbsent));
    }

    /// A scratch directory under the system temp dir, removed on drop.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("shekyl-info-facts-{tag}-{}", std::process::id()));
            drop(std::fs::remove_dir_all(&dir));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.0));
        }
    }

    #[test]
    fn a_data_file_reports_its_length() {
        let scratch = Scratch::new("length");
        let file = scratch.0.join("data.mdb");
        std::fs::write(&file, vec![0u8; 4097]).expect("write data file");
        assert_eq!(store_file_size(&file), Ok(4097));
    }

    /// An empty store is a size of zero, and it is an answer.
    #[test]
    fn an_empty_data_file_is_zero_and_not_a_fault() {
        let scratch = Scratch::new("empty");
        let file = scratch.0.join("data.mdb");
        std::fs::write(&file, []).expect("write data file");
        assert_eq!(store_file_size(&file), Ok(0));
    }

    /// The case the store's own size getter answers `0` for. An unreadable
    /// data file is the fault, never a size.
    #[test]
    fn a_missing_data_file_is_the_fault_and_never_a_size_of_zero() {
        let scratch = Scratch::new("missing");
        let file = scratch.0.join("data.mdb");
        assert_eq!(store_file_size(&file), Err(FactsFault::StoreUnreadable));
    }

    /// A path that exists and is not a file has no size to mean.
    #[test]
    fn a_directory_where_the_data_file_should_be_is_the_fault() {
        let scratch = Scratch::new("directory");
        assert_eq!(
            store_file_size(&scratch.0),
            Err(FactsFault::StoreUnreadable)
        );
    }

    /// A data file inside a directory the process may not search cannot be
    /// stat'ed: the fault, not a size. Skipped for a superuser, whom the
    /// permission does not stop.
    #[cfg(unix)]
    #[test]
    fn a_data_file_the_process_may_not_stat_is_the_fault() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = Scratch::new("denied");
        let locked = scratch.0.join("locked");
        std::fs::create_dir(&locked).expect("create locked dir");
        let file = locked.join("data.mdb");
        std::fs::write(&file, [1u8; 16]).expect("write data file");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("lock the dir");
        let stat = std::fs::metadata(&file);
        let verdict = store_file_size(&file);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
            .expect("unlock the dir");
        if stat.is_ok() {
            // Running as a superuser: the permission is not enforced, so
            // there is no unreadable file here to test.
            return;
        }
        assert_eq!(verdict, Err(FactsFault::StoreUnreadable));
    }
}
