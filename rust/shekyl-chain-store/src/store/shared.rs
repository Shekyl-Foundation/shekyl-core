// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! State a live [`WriteBatch`](super::WriteBatch) shares with its store.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::family_set::FamilySet;
use crate::provenance::Provenance;

/// The one-live-write guard and the in-memory mirror of the provenance cell.
pub(super) struct Shared {
    write_held: AtomicBool,
    /// [`FamilySet::bits`] of the persisted `apply_policy` cell, as this
    /// process last saw or wrote it. Only ever widened (`fetch_or`), so it
    /// can never read as *less* tainted than the file.
    stubbed_bits: AtomicU32,
}

impl Shared {
    pub(super) fn new(provenance: Provenance) -> Self {
        Self {
            write_held: AtomicBool::new(false),
            stubbed_bits: AtomicU32::new(provenance.stubbed().bits()),
        }
    }

    /// Claim the single write slot. `false` if it is already held.
    pub(super) fn try_hold_write(&self) -> bool {
        self.write_held
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Release the write slot.
    pub(super) fn release_write(&self) {
        self.write_held.store(false, Ordering::Release);
    }

    /// The provenance as this process last saw it.
    pub(super) fn provenance(&self) -> Provenance {
        let bits = self.stubbed_bits.load(Ordering::Acquire);
        Provenance::of(
            FamilySet::from_bits(bits)
                .expect("the mirror is only ever widened by valid FamilySet bits"),
        )
    }

    /// Widen the mirror to include `provenance`. Monotone.
    pub(super) fn taint(&self, provenance: Provenance) {
        self.stubbed_bits
            .fetch_or(provenance.stubbed().bits(), Ordering::AcqRel);
    }
}
