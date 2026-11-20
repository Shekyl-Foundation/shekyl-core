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
//! a session registers under the index's lock, checking the enrollment again
//! there ([`Sessions::register`]), and every change to an enrollment is made
//! under the same lock ([`Sessions::change`]): whichever comes second sees
//! the first.
//!
//! **A key holds at most `SESSIONS_PER_CLIENT` sessions** (RT-O37). The
//! count is read under the same lock, so two sessions registering at once
//! cannot both take the last place.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use shekyl_rpc_channel::SESSIONS_PER_CLIENT;
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

/// What a registration came to.
pub enum Registration {
    /// The session joined the index.
    Registered(Session),
    /// The enrollment no longer admits it: removed, or its ceiling lowered.
    NotAdmitted,
    /// The key already holds [`SESSIONS_PER_CLIENT`] sessions.
    AtCap,
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

    /// Register a session for `fingerprint` if `admitted` still says yes
    /// and the key holds fewer than [`SESSIONS_PER_CLIENT`], both asked
    /// under the index's lock.
    pub fn register(
        self: &Arc<Self>,
        fingerprint: [u8; 32],
        admitted: impl FnOnce() -> bool,
    ) -> Registration {
        let mut index = self.lock();
        if !admitted() {
            return Registration::NotAdmitted;
        }
        let open = index.entry(fingerprint).or_default();
        if open.len() >= SESSIONS_PER_CLIENT {
            return Registration::AtCap;
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (close, closed) = watch::channel(false);
        open.push((id, close));
        drop(index);
        Registration::Registered(Session {
            sessions: Arc::clone(self),
            fingerprint,
            id,
            closed,
        })
    }

    /// Change an enrollment under the index's lock: `change` writes the store
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

    fn registered(registration: Registration) -> Session {
        match registration {
            Registration::Registered(session) => session,
            Registration::NotAdmitted => panic!("not admitted"),
            Registration::AtCap => panic!("at the cap"),
        }
    }

    /// Closing a fingerprint closes each of its sessions and no other's; a
    /// dropped session leaves the index. Red edit: make `close` a no-op,
    /// and the first session never sees its close.
    #[tokio::test]
    async fn closing_a_fingerprint_closes_its_sessions_only() {
        let sessions = Arc::new(Sessions::default());
        let mut a1 = registered(sessions.register([1; 32], || true));
        let mut a2 = registered(sessions.register([1; 32], || true));
        let b = registered(sessions.register([2; 32], || true));
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
        assert!(matches!(
            sessions.register([3; 32], || false),
            Registration::NotAdmitted
        ));
        assert_eq!(sessions.open(&[3; 32]), 0);
    }

    /// A key holds at most `SESSIONS_PER_CLIENT` sessions; another key is
    /// not affected, and a closed session frees its place. Red edit: drop
    /// the count test in `register`, and the fifth session registers.
    #[test]
    fn a_key_past_its_cap_is_refused_and_a_closed_session_frees_a_place() {
        let sessions = Arc::new(Sessions::default());
        let mut held: Vec<Session> = (0..SESSIONS_PER_CLIENT)
            .map(|_| registered(sessions.register([4; 32], || true)))
            .collect();
        assert!(matches!(
            sessions.register([4; 32], || true),
            Registration::AtCap
        ));
        assert_eq!(sessions.open(&[4; 32]), SESSIONS_PER_CLIENT);
        let other = registered(sessions.register([5; 32], || true));
        held.pop();
        let again = registered(sessions.register([4; 32], || true));
        assert_eq!(sessions.open(&[4; 32]), SESSIONS_PER_CLIENT);
        drop((held, other, again));
        assert_eq!(sessions.open(&[4; 32]), 0);
    }
}
