// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The stores' read-only checks ([`ChainStore::check_with_genesis`],
//! [`PoolStore::check`]): each writes nothing, whatever it finds, and
//! refuses exactly what the store's open refuses on the file.

use shekyl_chain_rules::GenesisPin;

use super::store_tests::{production_horizons, EPOCH};
use super::{ChainStore, StoreCheck};
use crate::apply_policy::ApplyPolicy;
use crate::pool::PoolStore;
use crate::redb_recovery::{bytes_and_mtime, mark_recovery_required};
use crate::test_paths::tmp;

/// Bytes no store wrote, too long to be an unfinished initialization.
const FOREIGN: &[u8] = b"these bytes were never a redb database, and are not an empty file";

fn any_genesis() -> GenesisPin {
    GenesisPin::for_tests(None)
}

fn check_chain(path: &std::path::Path) -> Result<StoreCheck, super::StoreError> {
    ChainStore::check_with_genesis(path, production_horizons(), &any_genesis())
}

/// Every file the chain check finds is left as it was: an absent one is
/// not created, and a sealed, a dirty, an unfinished and a foreign file
/// keep their bytes and modification time. The foreign file is the open's
/// refusal too, in the open's words. Red edit: check with a writable open.
#[test]
fn the_chain_check_writes_nothing_and_refuses_what_the_open_refuses() {
    let absent = tmp("check-chain-absent");
    assert_eq!(
        check_chain(absent.as_ref()).expect("absent"),
        StoreCheck::Absent
    );
    assert!(!absent.as_ref().exists(), "the check created the file");

    let sealed = tmp("check-chain-sealed");
    drop(ChainStore::create(&sealed, EPOCH).expect("a sealed store"));
    let before = bytes_and_mtime(&sealed);
    assert_eq!(
        check_chain(sealed.as_ref()).expect("sealed"),
        StoreCheck::Admitted
    );
    assert_eq!(
        bytes_and_mtime(&sealed),
        before,
        "a sealed file was written"
    );

    mark_recovery_required(&sealed);
    let before = bytes_and_mtime(&sealed);
    assert_eq!(
        check_chain(sealed.as_ref()).expect("dirty"),
        StoreCheck::NeedsRepair
    );
    assert_eq!(
        bytes_and_mtime(&sealed),
        before,
        "a dirty file was repaired"
    );

    let unfinished = tmp("check-chain-unfinished");
    std::fs::write(&unfinished, []).expect("an empty file");
    let before = bytes_and_mtime(&unfinished);
    assert_eq!(
        check_chain(unfinished.as_ref()).expect("empty"),
        StoreCheck::Unfinished
    );
    assert_eq!(
        bytes_and_mtime(&unfinished),
        before,
        "an unfinished file was moved"
    );

    let foreign = tmp("check-chain-foreign");
    std::fs::write(&foreign, FOREIGN).expect("a foreign file");
    let before = bytes_and_mtime(&foreign);
    let checked = check_chain(foreign.as_ref()).expect_err("a foreign file is refused");
    assert_eq!(
        bytes_and_mtime(&foreign),
        before,
        "a foreign file was written"
    );
    let Err(opened) = ChainStore::with_genesis(
        &foreign,
        ApplyPolicy::Full,
        production_horizons(),
        &any_genesis(),
    ) else {
        panic!("the open accepted a file the check refused");
    };
    assert_eq!(
        checked.to_string(),
        opened.to_string(),
        "the check and the open differ"
    );
}

/// The pool check, the same: nothing written, whatever it finds, and the
/// open's refusal for a file the pool does not own. Red edit: check with a
/// writable open.
#[test]
fn the_pool_check_writes_nothing_and_refuses_what_the_open_refuses() {
    let absent = tmp("check-pool-absent");
    assert_eq!(
        PoolStore::check(&absent).expect("absent"),
        StoreCheck::Absent
    );
    assert!(!absent.as_ref().exists(), "the check created the file");

    let sealed = tmp("check-pool-sealed");
    drop(PoolStore::create(&sealed).expect("a sealed pool"));
    let before = bytes_and_mtime(&sealed);
    assert_eq!(
        PoolStore::check(&sealed).expect("sealed"),
        StoreCheck::Admitted
    );
    assert_eq!(
        bytes_and_mtime(&sealed),
        before,
        "a sealed file was written"
    );

    mark_recovery_required(&sealed);
    let before = bytes_and_mtime(&sealed);
    assert_eq!(
        PoolStore::check(&sealed).expect("dirty"),
        StoreCheck::NeedsRepair
    );
    assert_eq!(
        bytes_and_mtime(&sealed),
        before,
        "a dirty file was repaired"
    );

    let unfinished = tmp("check-pool-unfinished");
    std::fs::write(&unfinished, []).expect("an empty file");
    let before = bytes_and_mtime(&unfinished);
    assert_eq!(
        PoolStore::check(&unfinished).expect("empty"),
        StoreCheck::Unfinished
    );
    assert_eq!(
        bytes_and_mtime(&unfinished),
        before,
        "an unfinished file was moved"
    );

    let foreign = tmp("check-pool-foreign");
    std::fs::write(&foreign, FOREIGN).expect("a foreign file");
    let before = bytes_and_mtime(&foreign);
    let checked = PoolStore::check(&foreign).expect_err("a foreign file is refused");
    assert_eq!(
        bytes_and_mtime(&foreign),
        before,
        "a foreign file was written"
    );
    let Err(opened) = PoolStore::create(&foreign) else {
        panic!("the open accepted a file the check refused");
    };
    assert_eq!(
        checked.to_string(),
        opened.to_string(),
        "the check and the open differ"
    );
}
