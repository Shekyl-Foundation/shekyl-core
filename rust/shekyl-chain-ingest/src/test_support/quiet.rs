// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A test's wait for a quiet hasher.
//!
//! The wait returns the resident, or [`Unquiet`]: the bound passed, or
//! the hasher stopped. A caller that knows what the hasher should rest
//! on says so with [`Unquiet::expected`]. The wait itself has no
//! expectation to invent.

use std::collections::BTreeSet;
use std::time::Duration;

use shekyl_hasher::Resident;
use tokio::sync::watch::Receiver;

/// How long a hasher may take to go quiet before a test that waits for it
/// fails: the jobs in flight, and at most three derives. The loopback
/// harness holds a stopping chain to the same bound
/// (`shekyl-p2p-harness` `sync/chain.rs`). That harness waits until the
/// hasher is quiet *and* holds the list, because its ranker can still be
/// about to send. This wait does not: a caller that has already ranked
/// treats a quiet hasher on the wrong seeds as its own failure.
pub const QUIET_WITHIN: Duration = Duration::from_secs(120);

/// A test's wait for a quiet hasher ended without one.
///
/// `held` is the last [`Resident`] the watch published. The arms are
/// different facts: the bound passed while the hasher was still in
/// motion, or the hasher stopped and closed the watch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unquiet {
    /// [`QUIET_WITHIN`], or the shorter bound a test of this wait passes,
    /// elapsed first.
    TimedOut {
        /// How long the wait was willing to run.
        bound: Duration,
        /// What the hasher still held when the bound passed.
        held: Resident,
    },
    /// The hasher dropped its watch.
    Stopped {
        /// The last value the hasher published.
        held: Resident,
    },
}

impl std::fmt::Display for Unquiet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimedOut { bound, held } => write!(
                f,
                "the hasher did not go quiet within {bound:?}: it holds {held:?}"
            ),
            Self::Stopped { held } => write!(
                f,
                "the hasher stopped while a test waited for it to go quiet: it holds {held:?}"
            ),
        }
    }
}

impl Unquiet {
    /// Panic with this fact and `expected`, what the caller was waiting
    /// for the hasher to come to rest on.
    pub fn expected(self, expected: impl std::fmt::Debug) -> ! {
        panic!("{self}; expected: {expected:?}")
    }
}

/// What `resident` shows once the hasher is quiet
/// ([`Resident::quiet`]), or [`Unquiet`] when the wait ends without that.
///
/// A job, a lease or a build in flight is waited out, for at most
/// [`QUIET_WITHIN`]. The runtime this is polled on must have a timer:
/// `#[tokio::test]` and [`tokio::runtime::Runtime::new`] do, and a
/// current-thread builder needs
/// [`tokio::runtime::Builder::enable_time`].
///
/// This does not compare the places with a list. A caller that knows
/// what the hasher should rest on puts that on [`Unquiet::expected`].
pub async fn quiet_resident(resident: Receiver<Resident>) -> Result<Resident, Unquiet> {
    quiet_resident_within(QUIET_WITHIN, resident).await
}

/// How [`quiet_resident_within`]'s wait ended, after its watch ref is dropped.
enum WaitEnd {
    Quiet(Resident),
    Stopped,
    TimedOut,
}

/// [`quiet_resident`] under `bound`. The bound's own test passes a
/// shorter one; every other caller passes [`QUIET_WITHIN`].
async fn quiet_resident_within(
    bound: Duration,
    mut resident: Receiver<Resident>,
) -> Result<Resident, Unquiet> {
    // Drop the watch ref before the failure arms read `resident`.
    let ended = {
        match tokio::time::timeout(bound, resident.wait_for(|resident| resident.quiet)).await {
            Ok(Ok(quiet)) => WaitEnd::Quiet(quiet.clone()),
            Ok(Err(_)) => WaitEnd::Stopped,
            Err(_) => WaitEnd::TimedOut,
        }
    };
    let held = || resident.borrow().clone();
    match ended {
        WaitEnd::Quiet(quiet) => Ok(quiet),
        WaitEnd::Stopped => Err(Unquiet::Stopped { held: held() }),
        WaitEnd::TimedOut => Err(Unquiet::TimedOut {
            bound,
            held: held(),
        }),
    }
}

/// The seeds `hasher` holds once it is quiet ([`quiet_resident`]).
///
/// `expected` is what this caller is waiting for the hasher to rest on.
/// It is printed only when the wait returns [`Unquiet`].
///
/// # Panics
///
/// The hasher did not go quiet within [`QUIET_WITHIN`], or it stopped.
pub async fn quiet_seeds(
    hasher: &shekyl_hasher::Hasher,
    expected: impl std::fmt::Debug,
) -> BTreeSet<[u8; 32]> {
    match quiet_resident(hasher.resident()).await {
        Ok(quiet) => held_seeds(&quiet),
        Err(unquiet) => unquiet.expected(expected),
    }
}

/// The seeds `resident` holds, as [`named_seeds`] reports what a list names.
pub fn held_seeds(resident: &Resident) -> BTreeSet<[u8; 32]> {
    resident
        .caches
        .iter()
        .map(|(seed, _)| *seed.as_bytes())
        .collect()
}

/// What `list` names, as [`held_seeds`] reports what is held: none when
/// there is no list.
pub fn named_seeds(list: Option<&shekyl_hasher::Ranked>) -> BTreeSet<[u8; 32]> {
    list.into_iter()
        .flat_map(shekyl_hasher::Ranked::seeds)
        .map(|seed| *seed.as_bytes())
        .collect()
}

/// The quiet wait, over a watch channel. No hasher is started: the
/// subject is the bound and the two ways it can end, and a [`Resident`]
/// is a value. Test-only: `test_support` also compiles under the
/// `forge` feature, where these tests are not built.
#[cfg(test)]
mod quiet_wait {
    use std::time::Duration;

    use shekyl_hasher::{Residency, Resident};
    use shekyl_pow_randomx::Seedhash;

    use super::{quiet_resident_within, Unquiet};

    /// Shorter than [`super::QUIET_WITHIN`]. This test waits the bound,
    /// so the bound is this long and no longer.
    const BOUND: Duration = Duration::from_millis(250);

    fn leased() -> Resident {
        Resident {
            caches: vec![(Seedhash::from_bytes([0x5e; 32]), Residency::Leased)],
            builds: 0,
            build_ns: 0,
            quiet: false,
        }
    }

    /// A watch left leased fails when [`BOUND`] passes, naming the bound
    /// and the place. The sender stays open, so this is the timeout and
    /// not a stop.
    ///
    /// Red edit: in `quiet_resident_within`, wait without the timeout.
    /// This hangs until the runner kills it.
    #[tokio::test]
    async fn a_wait_for_quiet_is_bounded_and_names_what_is_held() {
        let (keep, resident) = tokio::sync::watch::channel(leased());
        let unquiet = quiet_resident_within(BOUND, resident)
            .await
            .expect_err("a lease that is never returned is not quiet");
        let Unquiet::TimedOut { bound, held } = &unquiet else {
            panic!("the bound passed and the watch is still open: {unquiet}");
        };
        assert_eq!(*bound, BOUND);
        assert!(
            matches!(held.caches.as_slice(), [(_, Residency::Leased)]),
            "it names the place it holds: {held:?}"
        );
        let said = unquiet.to_string();
        assert!(said.contains("250ms"), "{said}");
        assert!(said.contains("Leased"), "{said}");
        drop(keep);
    }

    /// A dropped watch is the hasher stopping. The message says that,
    /// and it still names the place. It does not claim the bound passed.
    ///
    /// Red edit: report [`tokio::sync::watch::error::RecvError`] as
    /// [`Unquiet::TimedOut`]. The arm assert fails.
    #[tokio::test]
    async fn a_stopped_hasher_is_not_reported_as_a_timeout() {
        let (stop, resident) = tokio::sync::watch::channel(leased());
        drop(stop);
        let unquiet = quiet_resident_within(BOUND, resident)
            .await
            .expect_err("a stopped hasher is not quiet");
        let Unquiet::Stopped { held } = &unquiet else {
            panic!("the watch closed; this is not the bound: {unquiet}");
        };
        assert!(
            matches!(held.caches.as_slice(), [(_, Residency::Leased)]),
            "it names the place it held: {held:?}"
        );
        let said = unquiet.to_string();
        assert!(said.contains("stopped"), "{said}");
        assert!(!said.contains("250ms"), "a stop is not a timeout: {said}");
    }

    /// A hasher that is already quiet is that resident, at once.
    ///
    /// Red edit: treat the current value as a failure when `quiet` is
    /// already set. This `expect` fails.
    #[tokio::test]
    async fn a_hasher_that_is_already_quiet_is_that_resident() {
        let (keep, resident) = tokio::sync::watch::channel(Resident::default());
        let quiet = quiet_resident_within(BOUND, resident)
            .await
            .expect("already quiet");
        assert!(quiet.quiet);
        assert!(quiet.caches.is_empty());
        drop(keep);
    }
}
