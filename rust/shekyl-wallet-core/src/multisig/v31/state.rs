// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Per-intent state machine (PQC_MULTISIG.md SS13.1).
//!
//! Each intent progresses through a linear state sequence. Terminal states
//! are BROADCAST, REJECTED, and TIMED_OUT.

use serde::{Deserialize, Serialize};

/// Per-intent states (SS13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentState {
    Proposed,
    Verified,
    ProverReady,
    Signed,
    Assembled,
    Broadcast,
    Rejected,
    TimedOut,
}

impl IntentState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Broadcast | Self::Rejected | Self::TimedOut)
    }

    pub fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Proposed | Self::Verified | Self::ProverReady | Self::Signed
        )
    }
}

/// Tracked intent: state + metadata for the per-intent state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedIntent {
    pub intent_hash: [u8; 32],
    pub state: IntentState,
    pub proposer_index: u8,
    pub created_at: u64,
    pub expires_at: u64,
    pub tx_counter: u64,
    pub signatures_collected: u8,
    pub signatures_required: u8,
    pub veto_count: u8,
    pub rejection_reason: Option<String>,
}

impl TrackedIntent {
    pub fn new(
        intent_hash: [u8; 32],
        proposer_index: u8,
        created_at: u64,
        expires_at: u64,
        tx_counter: u64,
        m_required: u8,
    ) -> Self {
        Self {
            intent_hash,
            state: IntentState::Proposed,
            proposer_index,
            created_at,
            expires_at,
            tx_counter,
            signatures_collected: 0,
            signatures_required: m_required,
            veto_count: 0,
            rejection_reason: None,
        }
    }

    /// Attempt a state transition. Returns Ok(new_state) or Err if invalid.
    pub fn transition(&mut self, to: IntentState) -> Result<IntentState, StateError> {
        if self.state.is_terminal() {
            return Err(StateError::AlreadyTerminal(self.state));
        }

        match (&self.state, &to) {
            (IntentState::Proposed, IntentState::Verified) => {}
            (IntentState::Verified, IntentState::ProverReady) => {}
            (IntentState::ProverReady, IntentState::Signed) => {}
            (IntentState::Signed, IntentState::Assembled) => {}
            (IntentState::Assembled, IntentState::Broadcast) => {}
            // Any active state can be rejected or timed out
            (s, IntentState::Rejected) if s.is_active() || *s == IntentState::Assembled => {}
            (s, IntentState::TimedOut) if s.is_active() => {}
            _ => {
                return Err(StateError::InvalidTransition {
                    from: self.state,
                    to,
                });
            }
        }

        self.state = to;
        Ok(to)
    }

    /// Check expiry against current time, transitioning to TimedOut if needed.
    pub fn check_expiry(&mut self, now_secs: u64) -> bool {
        if !self.state.is_terminal() && now_secs > self.expires_at {
            self.state = IntentState::TimedOut;
            true
        } else {
            false
        }
    }

    /// Record a collected signature. Returns true if threshold reached.
    pub fn record_signature(&mut self) -> bool {
        self.signatures_collected += 1;
        self.signatures_collected >= self.signatures_required
    }

    /// Record a veto. Returns the new veto count.
    pub fn record_veto(&mut self) -> u8 {
        self.veto_count += 1;
        self.veto_count
    }
}

/// Errors during state transitions.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("intent already in terminal state: {0:?}")]
    AlreadyTerminal(IntentState),
    #[error("invalid transition: {from:?} -> {to:?}")]
    InvalidTransition { from: IntentState, to: IntentState },
}

/// Per-group tx_counter tracker (SS13.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxCounterTracker {
    pub current: u64,
    pub confirmations_required: u64,
}

impl TxCounterTracker {
    pub fn new(initial: u64, confirmations: u64) -> Self {
        Self {
            current: initial,
            confirmations_required: confirmations,
        }
    }

    /// Advance counter after observing confirmed broadcast.
    /// Returns the new counter value, or None if already at or past target.
    pub fn advance_to(&mut self, target: u64) -> Option<u64> {
        if target > self.current {
            self.current = target;
            Some(self.current)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_transitions() {
        let mut ti = TrackedIntent::new([0xAA; 32], 0, 1000, 2000, 1, 2);
        assert_eq!(ti.state, IntentState::Proposed);

        ti.transition(IntentState::Verified).unwrap();
        assert_eq!(ti.state, IntentState::Verified);

        ti.transition(IntentState::ProverReady).unwrap();
        ti.transition(IntentState::Signed).unwrap();
        ti.transition(IntentState::Assembled).unwrap();
        ti.transition(IntentState::Broadcast).unwrap();
        assert!(ti.state.is_terminal());
    }

    #[test]
    fn terminal_state_rejects_transition() {
        let mut ti = TrackedIntent::new([0xAA; 32], 0, 1000, 2000, 1, 2);
        ti.transition(IntentState::Verified).unwrap();
        ti.transition(IntentState::ProverReady).unwrap();
        ti.transition(IntentState::Signed).unwrap();
        ti.transition(IntentState::Assembled).unwrap();
        ti.transition(IntentState::Broadcast).unwrap();

        assert!(matches!(
            ti.transition(IntentState::Rejected),
            Err(StateError::AlreadyTerminal(IntentState::Broadcast))
        ));
    }

    #[test]
    fn invalid_skip_transition() {
        let mut ti = TrackedIntent::new([0xAA; 32], 0, 1000, 2000, 1, 2);
        assert!(matches!(
            ti.transition(IntentState::ProverReady),
            Err(StateError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn rejection_from_any_active_state() {
        for start in [
            IntentState::Proposed,
            IntentState::Verified,
            IntentState::ProverReady,
            IntentState::Signed,
        ] {
            let mut ti = TrackedIntent::new([0xAA; 32], 0, 1000, 2000, 1, 2);
            ti.state = start;
            ti.transition(IntentState::Rejected).unwrap();
            assert_eq!(ti.state, IntentState::Rejected);
        }
    }

    #[test]
    fn timeout_from_active_state() {
        let mut ti = TrackedIntent::new([0xAA; 32], 0, 1000, 2000, 1, 2);
        ti.transition(IntentState::Verified).unwrap();
        ti.transition(IntentState::TimedOut).unwrap();
        assert!(ti.state.is_terminal());
    }

    #[test]
    fn check_expiry_transitions() {
        let mut ti = TrackedIntent::new([0xAA; 32], 0, 1000, 2000, 1, 2);
        assert!(!ti.check_expiry(1500));
        assert!(ti.check_expiry(2001));
        assert_eq!(ti.state, IntentState::TimedOut);
    }

    #[test]
    fn signature_threshold() {
        let mut ti = TrackedIntent::new([0xAA; 32], 0, 1000, 2000, 1, 2);
        assert!(!ti.record_signature());
        assert!(ti.record_signature());
    }

    #[test]
    fn tx_counter_advancement() {
        let mut tc = TxCounterTracker::new(5, 3);
        assert_eq!(tc.advance_to(6), Some(6));
        assert_eq!(tc.current, 6);
        assert_eq!(tc.advance_to(6), None);
        assert_eq!(tc.advance_to(5), None);
        assert_eq!(tc.advance_to(10), Some(10));
    }
}
