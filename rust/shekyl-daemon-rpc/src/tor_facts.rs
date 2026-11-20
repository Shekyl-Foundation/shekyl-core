// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What `daemon_status` reads of Tor: two asks of the daemon's Tor
//! supervisor (`TOR_SUPERVISOR.md` `TSR-Q4`, `TSR-Q12`; Rick, 2026-11-11).
//!
//! **Health** asks one boolean, `hiding`, the relay's verdict. It is its own
//! narrow ask, so a caller shown only Health causes no status read.
//! **Status** asks the whole status, in `shekyl-tor-status`'s shape, and is
//! made only on behalf of a caller shown Status (RK-D24). The supervisor
//! answers both under every `tor` setting.
//!
//! Both are asks of an actor, answered on its loop, so they are futures,
//! boxed so a trait object can return them without an `async-trait`
//! dependency.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use shekyl_tor_status::TorStatus;

use crate::chain_facts::FactsFault;

/// One ask's answer.
pub type TorFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, FactsFault>> + Send + 'a>>;

/// The daemon's Tor supervisor, as `daemon_status` asks it (`RK-D7`: one
/// trait, one production implementation, chosen by the composition root).
pub trait TorFacts: Send + Sync {
    /// Whether an address-hiding session exists now: the relay's verdict,
    /// the class part (IG-Q67).
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when the supervisor has stopped.
    fn hiding(&self) -> TorFuture<'_, bool>;

    /// The Tor status at the moment it is asked, every age taken then.
    /// Called only on behalf of a caller shown Status.
    ///
    /// # Errors
    ///
    /// [`FactsFault::NotReady`] when the supervisor has stopped.
    fn status(&self) -> TorFuture<'_, TorStatus>;
}

/// A Tor handle.
pub type TorHandle = Arc<dyn TorFacts>;

/// No supervisor is supplied: every ask is [`FactsFault::NotReady`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TorAbsent;

impl TorFacts for TorAbsent {
    fn hiding(&self) -> TorFuture<'_, bool> {
        Box::pin(async { Err(FactsFault::NotReady) })
    }

    fn status(&self) -> TorFuture<'_, TorStatus> {
        Box::pin(async { Err(FactsFault::NotReady) })
    }
}

/// What `daemon_status` read of Tor for one caller: `hiding` always, and
/// the status only for a caller shown Status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorRead {
    /// Health's boolean.
    pub hiding: bool,
    /// The Status part's Tor fields; `None` for a caller not shown Status.
    pub status: Option<TorStatus>,
}

/// Ask `tor` what a caller with `shown_status` reads: the status only when
/// it is shown (RK-D24).
///
/// # Errors
///
/// The first ask's fault.
pub async fn read(tor: &dyn TorFacts, shown_status: bool) -> Result<TorRead, FactsFault> {
    let hiding = tor.hiding().await?;
    let status = if shown_status {
        Some(tor.status().await?)
    } else {
        None
    };
    Ok(TorRead { hiding, status })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use shekyl_tor_status::{Clearnet, Origination, Posture, TorSetting};

    use super::*;

    /// A supervisor that counts what it was asked.
    #[derive(Default)]
    struct Counted {
        hiding: AtomicUsize,
        status: AtomicUsize,
    }

    impl TorFacts for Counted {
        fn hiding(&self) -> TorFuture<'_, bool> {
            self.hiding.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(true) })
        }

        fn status(&self) -> TorFuture<'_, TorStatus> {
            self.status.fetch_add(1, Ordering::Relaxed);
            Box::pin(async {
                Ok(TorStatus {
                    posture: Posture {
                        tor: TorSetting::Off,
                        clearnet: Clearnet::On,
                    },
                    origination: Origination::ClearnetOnly,
                    sync_connector: vec![],
                    tor_quiet: None,
                    tor: None,
                })
            })
        }
    }

    /// **A caller not shown Status causes no status read** (RK-D24; Rick,
    /// 2026-11-11: the narrow `hiding` ask). Every caller is asked
    /// `hiding`; only one shown Status asks the status. Fails if the read
    /// asks the status for every caller, or skips `hiding` for one.
    #[tokio::test]
    async fn a_caller_not_shown_status_causes_no_status_read() {
        let tor = Counted::default();
        let health = read(&tor, false).await.expect("answered");
        assert!(health.hiding);
        assert_eq!(health.status, None);
        assert_eq!(tor.hiding.load(Ordering::Relaxed), 1);
        assert_eq!(tor.status.load(Ordering::Relaxed), 0, "no status read");
        let status = read(&tor, true).await.expect("answered");
        assert!(status.status.is_some());
        assert_eq!(tor.hiding.load(Ordering::Relaxed), 2);
        assert_eq!(tor.status.load(Ordering::Relaxed), 1);
    }

    /// No supervisor is not an answer: both asks are not ready.
    #[tokio::test]
    async fn an_absent_supervisor_answers_not_ready() {
        assert_eq!(read(&TorAbsent, false).await, Err(FactsFault::NotReady));
        assert_eq!(read(&TorAbsent, true).await, Err(FactsFault::NotReady));
    }
}
