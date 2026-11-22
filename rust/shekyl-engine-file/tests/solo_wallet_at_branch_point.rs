// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A solo wallet written by `dev` at multisig 4a-2a's branch point
//! (`25745115a4`, ledger format 26) is refused by its ledger version, and
//! by nothing else.
//!
//! R-36 held until R-37: this branch opened that wallet and saved the same
//! ledger bytes back. The test that showed it ran at `6e35cbef15`, which
//! also holds the fixture's ledger builder. R-37 lets a send pay a group,
//! so the send journal and the wallet ledger change version
//! (`SEND_JOURNAL_BLOCK_VERSION` 7, `WALLET_LEDGER_FORMAT_VERSION` 27). The
//! version check is an exact match, so the same file now opens to the one
//! refusal that names the remedy: restore the wallet from its seed. It
//! must not open to a decode error at a shifted offset, and its keys must
//! still open: the bump is in the ledger, not the envelope.

use std::path::{Path, PathBuf};

use shekyl_address::Network;
use shekyl_engine_file::{SafetyOverrides, WalletFile, WalletFileError};
use shekyl_engine_state::{WalletLedgerError, WALLET_LEDGER_FORMAT_VERSION};

/// The password the fixture was sealed under.
const PASSWORD: &[u8] = b"r36-branch-point";
/// The ledger format `dev` wrote at the branch point.
const BRANCH_POINT_LEDGER_FORMAT_VERSION: u32 = 26;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/solo_wallet_at_branch_point")
}

/// The fixture's two files, copied where the test can open them.
fn copied_fixture(dir: &Path) -> PathBuf {
    for name in ["solo.wallet.keys", "solo.wallet"] {
        std::fs::copy(fixture_dir().join(name), dir.join(name)).expect("copy fixture");
    }
    dir.join("solo.wallet")
}

#[test]
fn a_solo_wallet_from_the_branch_point_is_refused_by_its_ledger_version() {
    let dir = tempfile::tempdir().unwrap();
    let base = copied_fixture(dir.path());
    let state_before = std::fs::read(&base).unwrap();

    let Err(err) = WalletFile::open(&base, PASSWORD, Network::Testnet, SafetyOverrides::none())
    else {
        panic!("a version-26 ledger is refused");
    };
    assert!(
        matches!(
            err,
            WalletFileError::Ledger(WalletLedgerError::UnsupportedFormatVersion { file, binary })
                if file == BRANCH_POINT_LEDGER_FORMAT_VERSION
                    && binary == WALLET_LEDGER_FORMAT_VERSION
        ),
        "got {err:?}"
    );
    assert_eq!(
        std::fs::read(&base).unwrap(),
        state_before,
        "a refused open leaves the state file as it was"
    );
}
