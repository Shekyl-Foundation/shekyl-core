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
//! - **Not read:** Status and Peers. Status is the start time, the
//!   volume's free space, the alt-block count, the build's version, and
//!   the store's size. Peers is the socket counts and the peerlist sizes.
//! - **Read, as for every caller of an online node:** the chain, the
//!   pool's broadcast count, and one snapshot of the board's handshaken
//!   sessions. Health's `has_peers` is that snapshot. An offline node
//!   skips it: offline binds no hub, and no sessions is configuration.
//!
//! The two connection counts are not a read of their own. When Status is
//! shown they are that same snapshot, per direction. A restricted reply
//! does not carry them. There is no further exception. Until RK-Q8 the
//! store's size was read for every caller, because a restricted reply
//! carried it rounded up; that read ended with the stand-ins.
//!
//! **This trait is the contract the store cutover inherits.** Today its one
//! implementation reads the C++ core through the facts shim. When the Rust
//! store replaces the C++ one, the implementation changes and this does
//! not — which is why the rules that matter are stated here, on the trait,
//! and tested against a double, rather than left to the C++ side to get
//! right. Three in particular:
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

/// The Peers part's facts: whether P2P runs, and when it does, its counts
/// (Rick, 2026-10-14). [`InfoPeersFacts`] is reached only through
/// [`PeerFacts::Running`]; a daemon started with P2P off has no counts to
/// read, and [`PeerFacts::Off`] carries nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerFacts {
    Running(InfoPeersFacts),
    Off,
}

/// Per-connector transport and peerlist detail of a daemon whose P2P runs.
/// Read only for a caller who is shown Peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InfoPeersFacts {
    pub public_incoming_sockets: u64,
    pub public_outgoing_sockets: u64,
    pub tor_incoming_sockets: u64,
    pub tor_outgoing_sockets: u64,
    pub white_peerlist_size: u64,
    pub grey_peerlist_size: u64,
}

/// Which of the pool's two counts a caller is owed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolScope {
    /// The entries this node has broadcast: what every caller may be told.
    Broadcast,
    /// That, and the entries it holds and has not yet broadcast. The second
    /// is host-only data (`RPC_CHANNEL.md` §6.1, RT-O9.3).
    WithUnbroadcast,
}

/// The pool's population, as counts of one pool state.
///
/// The split is by **broadcast** state, which is what the pool's own filter
/// and the origin guard go by. It is not "relayed": a transaction on its
/// stem has been relayed, to one peer, and has not been broadcast, and it
/// is exactly the entry the second count exists to keep from other callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolCounts {
    /// Entries this node has broadcast.
    pub broadcast: u64,
    /// Entries it holds and has not yet broadcast. `None` when the read was
    /// made with [`PoolScope::Broadcast`]: the count was then not made, so
    /// there is no number here to leak or to mistake for zero.
    pub unbroadcast: Option<u64>,
}

/// The reads behind `get_info`.
pub trait InfoFacts: Send + Sync {
    /// The chain at its tip. One chain state: see the module docs.
    fn chain(&self) -> Result<InfoChainFacts, FactsFault>;
    /// The pool's population. With [`PoolScope::WithUnbroadcast`] both
    /// counts are of one pool state, read under one hold of the pool's lock;
    /// with [`PoolScope::Broadcast`] the second is not counted at all.
    fn pool_counts(&self, scope: PoolScope) -> Result<PoolCounts, FactsFault>;
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
    /// [`PeerFacts::Off`] for a daemon started with P2P off; an online
    /// daemon with no peer lists is a fault.
    fn peers(&self) -> Result<PeerFacts, FactsFault>;
    /// The node's sessions, per direction, from one snapshot of the seam
    /// board. Read for every caller of an online node: Health's `has_peers`
    /// is whether there is one, and Health is never withheld. Not read for
    /// a node that [`InfoChainFacts::offline`] says is offline, which binds
    /// no hub and has no sessions by configuration.
    ///
    /// The two counts are also Status members. They and `has_peers` are
    /// this one read and one definition of a session, so a reply cannot say
    /// a node has peers and no connections, or the reverse.
    ///
    /// # Errors
    ///
    /// [`FactsFault::HubAbsent`] when the p2p hub is not up. Zero sessions
    /// is an answer — a node with nobody to talk to — and is never returned
    /// for a hub that is not there.
    fn sessions(&self) -> Result<SessionCounts, FactsFault>;
}

/// The node's p2p sessions, on every connector, from one board snapshot.
///
/// **A session has finished its handshake** (RK-Q4, and RK-Q3 as ruled
/// 2026-10-12). A row before its handshake is a socket: it cannot relay,
/// the Peers part's socket counts already report it, and an inbound one
/// costs whoever opened it almost nothing, so counting it would let anyone
/// inflate this node's reported connectivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionCounts {
    /// Handshaken sessions this node opened.
    pub outbound: u64,
    /// Handshaken sessions opened to this node.
    pub inbound: u64,
}

impl SessionCounts {
    /// No sessions: what an offline node has, by configuration.
    pub const NONE: Self = Self {
        outbound: 0,
        inbound: 0,
    };

    /// Whether the node has a peer it can relay through: a session in
    /// either direction. The one definition of `has_peers`; it is not
    /// stored beside the counts, so it cannot disagree with them.
    #[must_use]
    pub const fn has_peers(self) -> bool {
        self.outbound > 0 || self.inbound > 0
    }
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
            protocol_version: u64::from(pod.protocol_version),
        })
    }

    fn pool_counts(&self, scope: PoolScope) -> Result<PoolCounts, FactsFault> {
        let (broadcast, unbroadcast) = self
            .core
            .info_pool_counts(scope == PoolScope::WithUnbroadcast)
            .map_err(FactsFault::from_code)?;
        Ok(PoolCounts {
            broadcast,
            unbroadcast,
        })
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

    fn peers(&self) -> Result<PeerFacts, FactsFault> {
        // The two list sizes come from the Rust peer lists, not the core,
        // and are read first: a daemon started with P2P off answers that
        // there, and no count is read for it.
        let (white_peerlist_size, grey_peerlist_size) =
            match crate::core::CoreRpc::peerlist_sizes().map_err(FactsFault::from_code)? {
                crate::core::P2pRead::Off => return Ok(PeerFacts::Off),
                crate::core::P2pRead::Running(sizes) => sizes,
            };
        let pod = self.core.info_peers().map_err(FactsFault::from_code)?;
        Ok(PeerFacts::Running(InfoPeersFacts {
            public_incoming_sockets: pod.public_incoming_sockets,
            public_outgoing_sockets: pod.public_outgoing_sockets,
            tor_incoming_sockets: pod.tor_incoming_sockets,
            tor_outgoing_sockets: pod.tor_outgoing_sockets,
            white_peerlist_size,
            grey_peerlist_size,
        }))
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

        let pod = |outbound, inbound| SeamSessionCountsFfi { outbound, inbound };
        assert_eq!(
            sessions_from(SHEKYL_SEAM_COUNT_OK, pod(0, 0)),
            Ok(SessionCounts::NONE)
        );
        assert_eq!(
            sessions_from(SHEKYL_SEAM_COUNT_OK, pod(8, 12)),
            Ok(SessionCounts {
                outbound: 8,
                inbound: 12,
            }),
            "each count lands in its own member"
        );
        assert_eq!(
            sessions_from(SHEKYL_SEAM_COUNT_ERR_NO_HUB, pod(0, 0)),
            Err(FactsFault::HubAbsent),
            "no hub is not zero sessions, whatever the slots hold"
        );
        assert_eq!(sessions_from(-1, pod(0, 0)), Err(FactsFault::Unknown(-1)));
        assert_eq!(sessions_from(1, pod(3, 3)), Err(FactsFault::Unknown(1)));
    }

    /// `has_peers` is a session in either direction, and only that.
    #[test]
    fn has_peers_is_a_session_in_either_direction() {
        for (outbound, inbound, expected) in [
            (0, 0, false),
            (1, 0, true),
            (0, 1, true),
            (8, 12, true),
            (u64::MAX, u64::MAX, true),
        ] {
            assert_eq!(
                SessionCounts { outbound, inbound }.has_peers(),
                expected,
                "{outbound} out, {inbound} in"
            );
        }
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
