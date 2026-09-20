// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The rig gate — and the split between what it can check and what it can only
//! record.
//!
//! `WALLET_SIDE_STORE.md` §6.3.4 pins five rig properties: device class, 64-bit
//! userland, 8 GB RAM, USB-SSD storage, sustained thermals. **Three of them are
//! observable from inside the process and two are not.** A gate advertising all
//! five while enforcing three would pass for the wrong reason — the shape
//! [`47-gate-subject-assertion`] exists to refuse — so this module enforces the
//! detectable ones and requires an explicit operator attestation for the rest,
//! recorded verbatim in the run record beside the measurement.
//!
//! The distinction is visible in the output: `enforced` names what the process
//! checked, `attested` names what a human asserted. A reader grading a run can
//! see which claims carry machine evidence.
//!
//! [`47-gate-subject-assertion`]: ../../../.cursor/rules/47-gate-subject-assertion.mdc

use serde::Serialize;
use std::fmt;

/// Rule 76's floor, as §6.3.4 restates it for this bench.
pub const REQUIRED_ARCH: &str = "aarch64";
/// 8 GB, in bytes, less a tolerance for firmware carve-out: a board that ships
/// 8 GB reports slightly under it, and grading must not turn on that gap.
pub const REQUIRED_RAM_BYTES: u64 = 7_500_000_000;

/// Strings that identify the pinned device in `/proc/cpuinfo`.
///
/// §6.3.4 pins *"Pi 4 Model B, Cortex-A72"*, and the device string **is**
/// observable — so it belongs on the enforced side, not the attested one.
/// Without this, any aarch64 host with 7.5 GB passed as the pinned rig, which
/// is a gate advertising a device check it never made.
///
/// **Board markers, not a core marker.** An earlier version also accepted
/// `Cortex-A72`, which is wrong in a way that reopens the hole it was added to
/// close: the A72 is a **CPU core**, shipped in many aarch64 boards that are
/// not a Pi 4, so accepting it graded any of them as the pinned rig. §6.3.4
/// pins the *board*. `Raspberry Pi 4` is the `Model` line and `BCM2711` the
/// `Hardware` line; both name the board, and the kernel answers with one or
/// the other depending on the field it populates.
pub const REQUIRED_DEVICE_MARKERS: &[&str] = &["Raspberry Pi 4", "BCM2711"];

/// What the operator asserts about the properties the process cannot see.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum StorageAttestation {
    /// `--attest-storage=usb-ssd`.
    UsbSsd,
    /// `--attest-storage=microsd` — recorded, and refused for grading.
    MicroSd,
    /// `--attest-storage=other`.
    Other,
}

/// The machine a run happened on.
#[derive(Clone, Debug, Serialize)]
pub struct Environment {
    /// `std::env::consts::ARCH`.
    pub arch: &'static str,
    /// Pointer width, in bits. §6.3.4: *"A 32-bit userland on the same board is
    /// a different machine for this work."*
    pub pointer_width_bits: usize,
    /// Total system memory, in bytes, or `None` where it could not be read.
    pub total_ram_bytes: Option<u64>,
    /// CPU model string, or `None` where it could not be read.
    pub cpu_model: Option<String>,
    /// Kernel release.
    pub kernel: Option<String>,
    /// The `shekyl-core` revision the harness was built from.
    pub git_revision: Option<String>,
}

impl Environment {
    /// Capture the current machine.
    #[must_use]
    pub fn capture() -> Self {
        Self {
            arch: std::env::consts::ARCH,
            pointer_width_bits: usize::BITS as usize,
            total_ram_bytes: read_total_ram_bytes(),
            cpu_model: read_cpu_model(),
            kernel: read_first_line("/proc/sys/kernel/osrelease"),
            git_revision: option_env!("SHEKYL_GIT_REVISION").map(str::to_owned),
        }
    }

    /// The three rig pins this process can actually observe.
    ///
    /// Returns every failure, not the first: an operator on the wrong machine
    /// should learn everything that is wrong about it in one run.
    ///
    /// # Errors
    /// [`RigMismatch`] naming each unmet pin.
    pub fn check_enforceable(&self) -> Result<(), RigMismatch> {
        let mut unmet = Vec::new();
        if self.arch != REQUIRED_ARCH {
            unmet.push(format!("arch is {}, rig pin is {REQUIRED_ARCH}", self.arch));
        }
        if self.pointer_width_bits != 64 {
            unmet.push(format!(
                "userland is {}-bit, rig pin is 64-bit",
                self.pointer_width_bits
            ));
        }
        match self.total_ram_bytes {
            Some(bytes) if bytes >= REQUIRED_RAM_BYTES => {}
            Some(bytes) => unmet.push(format!(
                "RAM is {bytes} B, rig pin is 8 GB (>= {REQUIRED_RAM_BYTES} B)"
            )),
            // Absence of signal is first evidence the subject is absent
            // (rule 47): an unreadable `/proc/meminfo` is a refusal to grade,
            // never an assumed pass.
            None => unmet.push("RAM could not be read; rig pin is 8 GB".to_string()),
        }
        match self.cpu_model.as_deref() {
            Some(model)
                if REQUIRED_DEVICE_MARKERS
                    .iter()
                    .any(|marker| model.contains(marker)) => {}
            Some(model) => unmet.push(format!(
                "device is {model:?}, rig pin is a Pi 4 Model B (one of {REQUIRED_DEVICE_MARKERS:?})"
            )),
            None => unmet.push(
                "the device model could not be read; rig pin is a Pi 4 Model B".to_string(),
            ),
        }
        if unmet.is_empty() {
            Ok(())
        } else {
            Err(RigMismatch { unmet })
        }
    }
}

/// The grading posture a run was invoked under.
#[derive(Clone, Debug, Serialize)]
pub struct RigVerdict {
    /// Whether this run may produce a graded verdict.
    pub grading: bool,
    /// The pins the process checked.
    pub enforced: Vec<String>,
    /// The pins a human asserted, recorded verbatim.
    pub attested: Vec<String>,
}

/// Decide whether a run may grade.
///
/// Measurement is always permitted — a dev-box run is useful, and refusing it
/// would push the schema's first review to the rig. Only *grading* is gated.
///
/// # Errors
/// [`RigMismatch`] when `--grade` was asked for on a machine or under an
/// attestation that does not meet the §6.3.4 pins.
pub fn decide(
    env: &Environment,
    grade_requested: bool,
    storage: Option<StorageAttestation>,
    thermal_steady_attested: bool,
) -> Result<RigVerdict, RigMismatch> {
    if !grade_requested {
        return Ok(RigVerdict {
            grading: false,
            enforced: vec!["not requested".to_string()],
            attested: vec!["not requested".to_string()],
        });
    }
    env.check_enforceable()?;

    let mut unmet = Vec::new();
    match storage {
        Some(StorageAttestation::UsbSsd) => {}
        Some(other) => unmet.push(format!(
            "--attest-storage={other} is not the rig pin (usb-ssd)"
        )),
        None => unmet.push(
            "--attest-storage is required to grade: the process cannot observe \
             the storage device"
                .to_string(),
        ),
    }
    if !thermal_steady_attested {
        unmet.push(
            "--attest-thermal-steady is required to grade: the process cannot \
             observe whether the board reached steady state"
                .to_string(),
        );
    }
    if !unmet.is_empty() {
        return Err(RigMismatch { unmet });
    }

    Ok(RigVerdict {
        grading: true,
        enforced: vec![
            format!("arch == {REQUIRED_ARCH}"),
            "userland == 64-bit".to_string(),
            format!("RAM >= {REQUIRED_RAM_BYTES} B"),
            format!("device matches one of {REQUIRED_DEVICE_MARKERS:?}"),
        ],
        attested: vec![
            "storage == usb-ssd".to_string(),
            "thermals == sustained steady state".to_string(),
        ],
    })
}

/// Why a run may not grade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RigMismatch {
    /// One entry per unmet pin.
    pub unmet: Vec<String>,
}

impl fmt::Display for RigMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "refusing to grade: {} (measurement is still available without --grade)",
            self.unmet.join("; ")
        )
    }
}

impl std::error::Error for RigMismatch {}

impl fmt::Display for StorageAttestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::UsbSsd => "usb-ssd",
            Self::MicroSd => "microsd",
            Self::Other => "other",
        };
        f.write_str(s)
    }
}

/// Whether a daemon endpoint names this machine.
///
/// §6.3.4 row 3's 5 s budget is defined for the **local** posture, and the
/// record hard-codes that claim — so grading a remote daemon against it is a
/// category error rather than a slow run: the verdict would be incomparable
/// with every other graded run while presenting as one of them.
///
/// **Delegated, not reimplemented.** The first version split the URL by hand
/// and tested `host.starts_with("127.")`, which accepts the remote hostname
/// `127.0.0.1.evil.com` — a prefix test on a *name* where an address was
/// meant. `shekyl_rpc_transport::network_posture` already owns this question
/// for the whole wallet: `host_of` handles userinfo and bracketed IPv6, and
/// `is_loopback_host` parses an actual IP literal before classifying it, so
/// `127.0.0.1.evil.com` is a name that does not parse and is refused. Its
/// module doc also records *why* the check is syntactic rather than
/// resolving — a resolver is a manipulable oracle, and consulting one would
/// leak the endpoint before the proxy decision. A second copy here would be a
/// second answer to drift.
#[must_use]
pub fn is_loopback_endpoint(url: &str) -> bool {
    shekyl_rpc_transport::network_posture::is_loopback_host(
        shekyl_rpc_transport::network_posture::host_of(url),
    )
}

fn read_first_line(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()?
        .lines()
        .next()
        .map(str::trim)
        .map(str::to_owned)
}

fn read_total_ram_bytes() -> Option<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kb.checked_mul(1024)
}

/// The device string, preferring the fields that name a **board**.
///
/// Order matters and is the opposite of the obvious one. `model name` is the
/// *core* (on the Pi 4: `ARMv7 Processor rev 3` on a 32-bit userland, absent
/// on 64-bit), while `Model` and `Hardware` name the board. Reading
/// `model name` first would hand the device check a string that cannot
/// identify a board even when the board is right there two lines below.
fn read_cpu_model() -> Option<String> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for key in ["Model", "Hardware", "model name"] {
        if let Some(line) = cpuinfo.lines().find(|l| l.starts_with(key)) {
            if let Some((_, value)) = line.split_once(':') {
                return Some(value.trim().to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "rig_tests.rs"]
mod tests;
