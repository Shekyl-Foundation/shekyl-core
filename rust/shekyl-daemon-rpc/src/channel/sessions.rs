// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Live channel sessions, indexed by client fingerprint (`RPC_CHANNEL.md`
//! §5): `rpc_client_remove` closes every session the fingerprint holds, and
//! so does an `rpc_client_set` that lowers its ceiling. There is no
//! mid-session downgrade: the client connects again for the new grant.
//!
//! **One lock decides.** Admission looks the fingerprint up before message 4,
//! and the session joins this index only after its first record opens. A
//! removal between the two would leave a session no index entry names. So
//! a session registers under the index's lock, checking the enrolment again
//! there ([`Sessions::register`]), and every change to an enrolment is made
//! under the same lock ([`Sessions::change`]): whichever comes second sees
//! the first.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::watch;

type Index = HashMap<[u8; 32], Vec<(u64, watch::Sender<bool>)>>;

/// The index.
#[derive(Default)]
pub struct Sessions {
    index: Mutex<Index>,
    next: AtomicU64,
}

/// One registered session. It leaves the index when dropped;
/// [`Self::closed`] resolves when its fingerprint is closed.
pub struct Session {
    sessions: Arc<Sessions>,
    fingerprint: [u8; 32],
    id: u64,
    closed: watch::Receiver<bool>,
}

impl Session {
    /// Resolves when this session's fingerprint is removed, or its ceiling
    /// lowered.
    pub async fn closed(&mut self) {
        drop(self.closed.wait_for(|&closed| closed).await);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let mut index = self.sessions.lock();
        if let Some(open) = index.get_mut(&self.fingerprint) {
            open.retain(|(id, _)| *id != self.id);
            if open.is_empty() {
                index.remove(&self.fingerprint);
            }
        }
    }
}

/// What a change under the lock asks of the index.
pub struct Changing<'a> {
    index: MutexGuard<'a, Index>,
}

impl Changing<'_> {
    /// Close every session `fingerprint` holds. Returns how many.
    pub fn close(&mut self, fingerprint: &[u8; 32]) -> usize {
        let Some(open) = self.index.remove(fingerprint) else {
            return 0;
        };
        for (_, close) in &open {
            close.send_replace(true);
        }
        open.len()
    }
}

impl Sessions {
    fn lock(&self) -> MutexGuard<'_, Index> {
        self.index.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Register a session for `fingerprint` if `admitted` still says yes,
    /// asked under the index's lock.
    pub fn register(
        self: &Arc<Self>,
        fingerprint: [u8; 32],
        admitted: impl FnOnce() -> bool,
    ) -> Option<Session> {
        let mut index = self.lock();
        if !admitted() {
            return None;
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (close, closed) = watch::channel(false);
        index.entry(fingerprint).or_default().push((id, close));
        drop(index);
        Some(Session {
            sessions: Arc::clone(self),
            fingerprint,
            id,
            closed,
        })
    }

    /// Change an enrolment under the index's lock: `change` writes the store
    /// and closes what it must.
    pub fn change<T>(&self, change: impl FnOnce(&mut Changing<'_>) -> T) -> T {
        let mut changing = Changing { index: self.lock() };
        change(&mut changing)
    }

    /// How many sessions `fingerprint` holds.
    #[must_use]
    pub fn open(&self, fingerprint: &[u8; 32]) -> usize {
        self.lock().get(fingerprint).map_or(0, Vec::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Closing a fingerprint closes each of its sessions and no other's; a
    /// dropped session leaves the index. Red edit: make `close` a no-op,
    /// and the first session never sees its close.
    #[tokio::test]
    async fn closing_a_fingerprint_closes_its_sessions_only() {
        let sessions = Arc::new(Sessions::default());
        let mut a1 = sessions.register([1; 32], || true).unwrap();
        let mut a2 = sessions.register([1; 32], || true).unwrap();
        let b = sessions.register([2; 32], || true).unwrap();
        assert_eq!(sessions.change(|c| c.close(&[1; 32])), 2);
        tokio::time::timeout(std::time::Duration::from_secs(1), a1.closed())
            .await
            .expect("closed");
        tokio::time::timeout(std::time::Duration::from_secs(1), a2.closed())
            .await
            .expect("closed");
        assert_eq!(sessions.open(&[2; 32]), 1);
        drop(b);
        assert_eq!(sessions.open(&[2; 32]), 0);
    }

    /// A registration the admission check refuses under the lock does not
    /// join the index.
    #[test]
    fn a_session_no_longer_admitted_is_not_registered() {
        let sessions = Arc::new(Sessions::default());
        assert!(sessions.register([3; 32], || false).is_none());
        assert_eq!(sessions.open(&[3; 32]), 0);
    }
}
