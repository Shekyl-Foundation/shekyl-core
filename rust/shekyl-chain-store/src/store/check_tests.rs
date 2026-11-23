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

/// A dangling link occupies the path: the writable open could not create a
/// store there, so the check refuses it and leaves it. Red edit: test the
/// path with `try_exists`, which follows the link and calls it absent.
#[cfg(unix)]
#[test]
fn a_dangling_link_at_a_store_path_is_refused_by_the_check() {
    let dir = tempfile::tempdir().expect("temp");
    let link = dir.path().join("store.db");
    std::os::unix::fs::symlink(dir.path().join("nothing-here"), &link).expect("the link");
    check_chain(&link).expect_err("the chain check admitted a dangling link");
    PoolStore::check(&link).expect_err("the pool check admitted a dangling link");
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("the link")
            .file_type()
            .is_symlink(),
        "the check replaced the link"
    );
    assert!(
        !dir.path().join("nothing-here").exists(),
        "the check created the link's target"
    );
}

/// Each check refuses exactly the file its open could not write, and leaves
/// it as it was. An account that may write anyway (root) is admitted. Red
/// edit: drop `claimable_at` from either check.
#[cfg(unix)]
#[test]
fn a_store_the_open_cannot_write_is_refused_by_the_check() {
    use std::os::unix::fs::PermissionsExt;
    let read_only = std::fs::Permissions::from_mode(0o400);

    let chain = tmp("check-chain-read-only");
    drop(ChainStore::create(&chain, EPOCH).expect("a sealed store"));
    std::fs::set_permissions(&chain, read_only.clone()).expect("read-only");
    let before = bytes_and_mtime(&chain);
    let writable = std::fs::OpenOptions::new().write(true).open(&chain).is_ok();
    assert_eq!(check_chain(chain.as_ref()).is_ok(), writable);
    assert_eq!(bytes_and_mtime(&chain), before, "the chain check wrote");

    let pool = tmp("check-pool-read-only");
    drop(PoolStore::create(&pool).expect("a pool"));
    std::fs::set_permissions(&pool, read_only).expect("read-only");
    let before = bytes_and_mtime(&pool);
    assert_eq!(PoolStore::check(pool.as_ref()).is_ok(), writable);
    assert_eq!(bytes_and_mtime(&pool), before, "the pool check wrote");
}

/// A live reader stops the writable open, so each check refuses in the
/// open's words while it holds the file, leaves the file as it was, and
/// admits it once the reader is gone. The claim the check took is released:
/// a writable open follows it. Red edit: make `probe_claim` a plain writable
/// `File` open, which sees no redb lock.
#[test]
fn a_store_a_live_reader_holds_is_refused_by_the_check() {
    let already_open = |refused: super::StoreError| {
        assert!(
            matches!(
                refused,
                super::StoreError::Engine(super::EngineError::Open(
                    redb::DatabaseError::DatabaseAlreadyOpen
                ))
            ),
            "{refused:?}"
        );
    };

    let chain = tmp("check-chain-live-reader");
    drop(ChainStore::create(&chain, EPOCH).expect("a sealed store"));
    let reader = redb::Builder::new()
        .open_read_only(&chain)
        .expect("a reader");
    let before = bytes_and_mtime(&chain);
    already_open(check_chain(chain.as_ref()).expect_err("a reader holds the chain file"));
    assert_eq!(bytes_and_mtime(&chain), before, "the chain check wrote");
    drop(reader);
    assert_eq!(
        check_chain(chain.as_ref()).expect("no reader"),
        StoreCheck::Admitted
    );
    assert_eq!(bytes_and_mtime(&chain), before, "the chain check wrote");
    drop(ChainStore::create(&chain, EPOCH).expect("the claim was released"));

    let pool = tmp("check-pool-live-reader");
    drop(PoolStore::create(&pool).expect("a pool"));
    let reader = redb::Builder::new()
        .open_read_only(&pool)
        .expect("a reader");
    let before = bytes_and_mtime(&pool);
    already_open(PoolStore::check(&pool).expect_err("a reader holds the pool file"));
    assert_eq!(bytes_and_mtime(&pool), before, "the pool check wrote");
    drop(reader);
    assert_eq!(
        PoolStore::check(&pool).expect("no reader"),
        StoreCheck::Admitted
    );
    assert_eq!(bytes_and_mtime(&pool), before, "the pool check wrote");
    drop(PoolStore::create(&pool).expect("the claim was released"));
}
