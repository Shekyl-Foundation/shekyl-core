// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Spawning a child that inherits one end of a connected pair, and nothing
//! else.
//!
//! **The contract: one lock per process, and a holder only spawns under it.**
//! [`spawn_lock`] is the process's one spawn lock. Every process start in a
//! process that hands an end to a child goes through it, and the code that
//! holds it does nothing but spawn: no wait for a child, no I/O, no second
//! call into the lock. On Windows a spawn hands every handle that is
//! inheritable at that moment to the child, so the window in which the
//! parent's copy of a child's end is inheritable must belong to that one
//! spawn; the lock is what makes it so. One lock per process means one copy
//! of this crate per process: a binary that linked two would hold two locks
//! and protect nothing.
//!
//! - [`spawn_lock`]: the lock, and `std` spawns taken under it.
//! - [`inherit`]: on Unix, a child keeps standard input, output and error and
//!   nothing else.
//! - [`pair`]: the connected pair, and the window that hands one end to a
//!   child and closes the parent's copy before the lock is released.
//!
//! Two launchers share it: the daemon's managed Tor, started holding its
//! owning control connection (`TOR_SUPERVISOR.md` `TSR-Q7`), and a GUI that
//! starts the daemon holding its owning connection (`GUI_SYNC_LANE.md` GS-C3).

pub mod inherit;
pub mod pair;
pub mod spawn_lock;
