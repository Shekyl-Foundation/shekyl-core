// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Test-only census of the floating-point work a hash does, for the
//! subnormal test (`vm::subnormal_tests`): every operand and result
//! the blocks see, classified, plus the two program shapes the
//! no-subnormal proof rests on. Per thread; nothing here reaches a
//! shipped binary.

use std::cell::RefCell;

pub(crate) use super::oracle::Op;

/// What the census has seen on this thread since the last [`take`].
#[derive(Clone, Debug, Default)]
pub(crate) struct Census {
    /// Operations by `[op][mode]`, packed (both lanes count once).
    pub(crate) ops: [[u64; 4]; 5],
    /// Subnormal operands seen, per lane.
    pub(crate) subnormal_inputs: u64,
    /// Subnormal results seen, per lane.
    pub(crate) subnormal_results: u64,
    /// NaN results seen, per lane.
    pub(crate) nan_results: u64,
    /// The most times one instruction ran in one iteration.
    pub(crate) max_runs_per_instruction: u16,
    /// The most FDIV_M instructions one program has on one E register.
    pub(crate) max_fdiv_m_per_e_register: u32,
    /// Iterations run.
    pub(crate) iterations: u64,
}

thread_local! {
    static CENSUS: RefCell<Census> = RefCell::new(Census::default());
}

/// Take this thread's census, leaving an empty one.
pub(crate) fn take() -> Census {
    CENSUS.with(|c| core::mem::take(&mut *c.borrow_mut()))
}

/// Record one packed operation (`b` is ignored for [`Op::Sqrt`]).
pub(crate) fn note(op: Op, mode: u32, a: [f64; 2], b: [f64; 2], r: [f64; 2]) {
    CENSUS.with(|c| {
        let mut c = c.borrow_mut();
        c.ops[op as usize][(mode & 3) as usize] += 1;
        for lane in 0..2 {
            let operands: &[f64] = if op == Op::Sqrt {
                &[a[lane]]
            } else {
                &[a[lane], b[lane]]
            };
            c.subnormal_inputs += operands.iter().filter(|x| x.is_subnormal()).count() as u64;
            c.subnormal_results += u64::from(r[lane].is_subnormal());
            c.nan_results += u64::from(r[lane].is_nan());
        }
    });
}

/// Record one iteration's shape: the most runs of any instruction in
/// it, and the most FDIV_M instructions its program has on one E
/// register.
pub(crate) fn note_iteration(max_runs: u16, max_fdiv_m: u32) {
    CENSUS.with(|c| {
        let mut c = c.borrow_mut();
        c.max_runs_per_instruction = c.max_runs_per_instruction.max(max_runs);
        c.max_fdiv_m_per_e_register = c.max_fdiv_m_per_e_register.max(max_fdiv_m);
        c.iterations += 1;
    });
}
