// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! Heartbeat protocol for liveness and censorship detection
//! (PQC_MULTISIG.md SS13.3).
//!
//! Members publish heartbeats at regular intervals. Comparison of heartbeats
//! detects missing members, relay censorship, operator diversity collapse,
//! tx_counter divergence, and time skew.

use serde::{Deserialize, Serialize};

/// Default heartbeat interval: 5 minutes in seconds.
pub const HEARTBEAT_INTERVAL_SECS: u64 = 300;

/// Maximum acceptable time skew between members (2 minutes).
pub const MAX_TIME_SKEW_SECS: u64 = 120;

/// Heartbeat message (SS13.3, message type 0x06).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Heartbeat {
    pub sender_index: u8,
    pub timestamp: u64,
    pub last_seen_intent: [u8; 32],
    pub observed_relay_ops: Vec<String>,
    pub local_tx_counter: u64,
    pub sig: Vec<u8>,
}

impl Heartbeat {
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.push(self.sender_index);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.last_seen_intent);
        buf.extend_from_slice(&(self.observed_relay_ops.len() as u32).to_le_bytes());
        for op in &self.observed_relay_ops {
            buf.extend_from_slice(&(op.len() as u32).to_le_bytes());
            buf.extend_from_slice(op.as_bytes());
        }
        buf.extend_from_slice(&self.local_tx_counter.to_le_bytes());
        buf
    }
}

/// Anomalies detected from heartbeat comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatAnomaly {
    MissingMember(u8),
    IntentDisagreement {
        member: u8,
        their_intent: [u8; 32],
    },
    RelayDiversityCollapse {
        member: u8,
        unique_operators: usize,
    },
    CounterDivergence {
        member: u8,
        their_counter: u64,
        our_counter: u64,
    },
    TimeSkew {
        member: u8,
        their_time: u64,
        our_time: u64,
    },
}

/// Per-member heartbeat tracker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatTracker {
    pub n_total: u8,
    pub last_seen: Vec<Option<u64>>,
    pub min_relay_operators: usize,
}

impl HeartbeatTracker {
    pub fn new(n_total: u8) -> Self {
        Self {
            n_total,
            last_seen: vec![None; n_total as usize],
            min_relay_operators: 3,
        }
    }

    /// Record a received heartbeat. Returns detected anomalies.
    pub fn record(
        &mut self,
        heartbeat: &Heartbeat,
        our_last_intent: &[u8; 32],
        our_tx_counter: u64,
        now_secs: u64,
    ) -> Vec<HeartbeatAnomaly> {
        let idx = heartbeat.sender_index as usize;
        if idx >= self.n_total as usize {
            return vec![];
        }

        self.last_seen[idx] = Some(now_secs);
        let mut anomalies = Vec::new();

        if heartbeat.last_seen_intent != *our_last_intent
            && *our_last_intent != [0; 32]
            && heartbeat.last_seen_intent != [0; 32]
        {
            anomalies.push(HeartbeatAnomaly::IntentDisagreement {
                member: heartbeat.sender_index,
                their_intent: heartbeat.last_seen_intent,
            });
        }

        let unique_ops: std::collections::HashSet<&str> = heartbeat
            .observed_relay_ops
            .iter()
            .map(|s| s.as_str())
            .collect();
        if unique_ops.len() < self.min_relay_operators {
            anomalies.push(HeartbeatAnomaly::RelayDiversityCollapse {
                member: heartbeat.sender_index,
                unique_operators: unique_ops.len(),
            });
        }

        if heartbeat.local_tx_counter != our_tx_counter {
            anomalies.push(HeartbeatAnomaly::CounterDivergence {
                member: heartbeat.sender_index,
                their_counter: heartbeat.local_tx_counter,
                our_counter: our_tx_counter,
            });
        }

        if now_secs.abs_diff(heartbeat.timestamp) > MAX_TIME_SKEW_SECS {
            anomalies.push(HeartbeatAnomaly::TimeSkew {
                member: heartbeat.sender_index,
                their_time: heartbeat.timestamp,
                our_time: now_secs,
            });
        }

        anomalies
    }

    /// Check for missing members that haven't sent a heartbeat recently.
    pub fn check_missing(&self, now_secs: u64, our_index: u8) -> Vec<HeartbeatAnomaly> {
        let mut missing = Vec::new();
        for i in 0..self.n_total {
            if i == our_index {
                continue;
            }
            match self.last_seen[i as usize] {
                None => missing.push(HeartbeatAnomaly::MissingMember(i)),
                Some(ts) if now_secs.saturating_sub(ts) > HEARTBEAT_INTERVAL_SECS * 3 => {
                    missing.push(HeartbeatAnomaly::MissingMember(i));
                }
                _ => {}
            }
        }
        missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_signable_bytes_deterministic() {
        let hb = Heartbeat {
            sender_index: 1,
            timestamp: 1000,
            last_seen_intent: [0xAA; 32],
            observed_relay_ops: vec!["op1".into(), "op2".into(), "op3".into()],
            local_tx_counter: 5,
            sig: vec![0; 64],
        };
        assert_eq!(hb.signable_bytes(), hb.signable_bytes());
    }

    #[test]
    fn tracker_detects_intent_disagreement() {
        let mut tracker = HeartbeatTracker::new(3);
        let hb = Heartbeat {
            sender_index: 1,
            timestamp: 1000,
            last_seen_intent: [0xBB; 32],
            observed_relay_ops: vec!["a".into(), "b".into(), "c".into()],
            local_tx_counter: 5,
            sig: vec![],
        };
        let anomalies = tracker.record(&hb, &[0xAA; 32], 5, 1000);
        assert!(anomalies
            .iter()
            .any(|a| matches!(a, HeartbeatAnomaly::IntentDisagreement { .. })));
    }

    #[test]
    fn tracker_detects_relay_diversity_collapse() {
        let mut tracker = HeartbeatTracker::new(3);
        let hb = Heartbeat {
            sender_index: 1,
            timestamp: 1000,
            last_seen_intent: [0xAA; 32],
            observed_relay_ops: vec!["same_op".into(), "same_op".into()],
            local_tx_counter: 5,
            sig: vec![],
        };
        let anomalies = tracker.record(&hb, &[0xAA; 32], 5, 1000);
        assert!(anomalies
            .iter()
            .any(|a| matches!(a, HeartbeatAnomaly::RelayDiversityCollapse { .. })));
    }

    #[test]
    fn tracker_detects_counter_divergence() {
        let mut tracker = HeartbeatTracker::new(3);
        let hb = Heartbeat {
            sender_index: 1,
            timestamp: 1000,
            last_seen_intent: [0xAA; 32],
            observed_relay_ops: vec!["a".into(), "b".into(), "c".into()],
            local_tx_counter: 7,
            sig: vec![],
        };
        let anomalies = tracker.record(&hb, &[0xAA; 32], 5, 1000);
        assert!(anomalies.iter().any(|a| matches!(
            a,
            HeartbeatAnomaly::CounterDivergence {
                their_counter: 7,
                our_counter: 5,
                ..
            }
        )));
    }

    #[test]
    fn tracker_detects_time_skew() {
        let mut tracker = HeartbeatTracker::new(3);
        let hb = Heartbeat {
            sender_index: 1,
            timestamp: 500,
            last_seen_intent: [0xAA; 32],
            observed_relay_ops: vec!["a".into(), "b".into(), "c".into()],
            local_tx_counter: 5,
            sig: vec![],
        };
        let anomalies = tracker.record(&hb, &[0xAA; 32], 5, 1000);
        assert!(anomalies
            .iter()
            .any(|a| matches!(a, HeartbeatAnomaly::TimeSkew { .. })));
    }

    #[test]
    fn tracker_detects_missing_members() {
        let tracker = HeartbeatTracker::new(3);
        let missing = tracker.check_missing(2000, 0);
        assert_eq!(missing.len(), 2);
    }

    #[test]
    fn no_anomalies_on_healthy_heartbeat() {
        let mut tracker = HeartbeatTracker::new(3);
        let hb = Heartbeat {
            sender_index: 1,
            timestamp: 1000,
            last_seen_intent: [0xAA; 32],
            observed_relay_ops: vec!["a".into(), "b".into(), "c".into()],
            local_tx_counter: 5,
            sig: vec![],
        };
        let anomalies = tracker.record(&hb, &[0xAA; 32], 5, 1000);
        assert!(anomalies.is_empty());
    }
}
