// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The archival half of [`ChainView`](crate::view::ChainView), as one macro.
//!
//! [`archival_reads!`] is `#[macro_export]`, so it is named
//! `shekyl_chain_rules::archival_reads` wherever this module is loaded.

/// Implement every archival [`ChainView`] read (A1–A9, A11–A22) as one policy.
///
/// Three policies, one method list. A new archival read is added here, once;
/// every view that expands the macro then implements it. A view that answers
/// from real rows (the store's `BatchView`) writes its own methods and
/// does not expand this.
///
/// * `archival_reads!(empty)` — no bonds: `None`, empty, `PassCount::ZERO`,
///   `false`. The `Ok` is any `Self::Fault`, including [`Infallible`](core::convert::Infallible).
/// * `archival_reads!(empty, r_market from <path>, sigma_work from <path>,
///   budget from <path>, complete_trees from <path>, slash_watermark from <path>)`
///   — `empty`, except that five reads answer from `self.<path>`:
///   `r_market` from a `BTreeMap<(ShardId, SettlementEpoch), RMarket>` of
///   planted prices, `sigma_work`, `budget` and `complete_trees` each from
///   a map keyed by epoch, and `last_settled_slash_epoch` from an
///   `Option<SettlementEpoch>`. The archival reads a no-bonds view may
///   plant: CEN-J15's accept needs a shard priced at the slash watermark,
///   CEN-J25's refusal an epoch that is closed and settled, CEN-J23's a
///   closed epoch that is not yet settled, and no driven chain in the tree
///   reaches any of them (`rules/tx_bond.rs`, J15's witness note;
///   `rules/tx_emission_against.rs`). These are settled values the close
///   and the slash pass wrote, not records, so planting them tests no
///   construction. `complete_trees` is its own map: a planted `Σwork` does
///   not invent a set (SI-31). An absent key stays `None`.
/// * `archival_reads!(fault <expr>)` — every read returns `Err(<expr>)`.
///   The expression is pasted into each method, so it is a unit constructor
///   or another value that is cheap to repeat.
/// * `archival_reads!(delegate <field>)` — each read is `self.<field>.the_method(...)`.
///   `<field>` names the inner view; the expansion writes `self` inside each method.
///
/// Paths are absolute so the expansion compiles in this crate and in a
/// downstream test view (`shekyl-chain-ingest`'s grown tree) without matching
/// imports.
#[macro_export]
macro_rules! archival_reads {
    (empty) => {
        $crate::archival_reads!(@methods {empty});
    };
    (
        empty,
        r_market from $($price:ident).+,
        sigma_work from $($sigma:ident).+,
        budget from $($budget:ident).+,
        complete_trees from $($trees:ident).+,
        slash_watermark from $($mark:ident).+
    ) => {
        $crate::archival_reads!(
            @methods {planted $($price).+ ; $($sigma).+ ; $($budget).+ ; $($trees).+ ; $($mark).+}
        );
    };
    (fault $err:expr) => {
        $crate::archival_reads!(@methods {fault $err});
    };
    (delegate $inner:ident) => {
        $crate::archival_reads!(@methods {delegate $inner});
    };
    (@methods $policy:tt) => {
        // One signature list. `@emit` writes the whole method, receiver and
        // body together: a nested macro may not name `self`.
        $crate::archival_reads!(@emit $policy; bond_record;
            (persona: &shekyl_types::PCanonicalId);
            (::core::option::Option<shekyl_types::archival::BondRecord>);
            (persona);
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; slash_log_after;
            (
                persona: &shekyl_types::PCanonicalId,
                height: shekyl_types::BlockHeight,
                floor: $crate::SlashLogFloor
            );
            (::std::vec::Vec<shekyl_types::archival::SlashLogEntry>);
            (persona, height, floor);
            (::std::vec::Vec::new()));
        $crate::archival_reads!(@emit $policy; last_served_epoch;
            (persona: &shekyl_types::PCanonicalId, shard: shekyl_types::ShardId);
            (::core::option::Option<shekyl_types::SettlementEpoch>);
            (persona, shard);
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; served_shards;
            (persona: &shekyl_types::PCanonicalId);
            (::std::vec::Vec<shekyl_types::archival::ServedShard>);
            (persona);
            (::std::vec::Vec::new()));
        $crate::archival_reads!(@emit $policy; pass_count;
            (
                persona: &shekyl_types::PCanonicalId,
                shard: shekyl_types::ShardId,
                epoch: shekyl_types::SettlementEpoch
            );
            (shekyl_types::archival::PassCount);
            (persona, shard, epoch);
            (shekyl_types::archival::PassCount::ZERO));
        $crate::archival_reads!(@emit $policy; r_market;
            (
                shard: shekyl_types::ShardId,
                epoch: shekyl_types::SettlementEpoch,
                floor: $crate::EpochFloor<$crate::Pricing>
            );
            (::core::option::Option<shekyl_types::archival::RMarket>);
            (shard, epoch, floor);
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; sigma_work;
            (
                epoch: shekyl_types::SettlementEpoch,
                floor: $crate::EpochFloor<$crate::Claimable>
            );
            (::core::option::Option<shekyl_types::archival::SigmaWorkMilli>);
            (epoch, floor);
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; budget;
            (
                epoch: shekyl_types::SettlementEpoch,
                floor: $crate::EpochFloor<$crate::Claimable>
            );
            (::core::option::Option<shekyl_units::AtomicUnits>);
            (epoch, floor);
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; last_settled_slash_epoch;
            ();
            (::core::option::Option<shekyl_types::SettlementEpoch>);
            ();
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; bond_records;
            ();
            (::std::vec::Vec<(shekyl_types::PCanonicalId, shekyl_types::archival::BondRecord)>);
            ();
            (::std::vec::Vec::new()));
        $crate::archival_reads!(@emit $policy; slash_applied;
            (
                persona: &shekyl_types::PCanonicalId,
                shard: shekyl_types::ShardId,
                epoch: shekyl_types::SettlementEpoch,
                floor: $crate::EpochFloor<$crate::Settling>
            );
            (bool);
            (persona, shard, epoch, floor);
            (false));
        $crate::archival_reads!(@emit $policy; budget_accruing;
            (epoch: shekyl_types::SettlementEpoch);
            (::core::option::Option<shekyl_units::AtomicUnits>);
            (epoch);
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; settlement_row;
            (
                persona: &shekyl_types::PCanonicalId,
                shard: shekyl_types::ShardId,
                epoch: shekyl_types::SettlementEpoch,
                floor: $crate::EpochFloor<$crate::Claimable>
            );
            (::core::option::Option<shekyl_types::archival::SettlementRow>);
            (persona, shard, epoch, floor);
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; issued_draws;
            (
                epoch: shekyl_types::SettlementEpoch,
                floor: $crate::EpochFloor<$crate::Settling>
            );
            (::std::vec::Vec<shekyl_types::archival::IndexedDraw>);
            (epoch, floor);
            (::std::vec::Vec::new()));
        $crate::archival_reads!(@emit $policy; issued_digest;
            (
                epoch: shekyl_types::SettlementEpoch,
                floor: $crate::EpochFloor<$crate::Settling>
            );
            (shekyl_types::archival::IssuedDigest);
            (epoch, floor);
            (shekyl_types::archival::IssuedDigest::ZERO));
        $crate::archival_reads!(@emit $policy; served_at;
            (
                persona: &shekyl_types::PCanonicalId,
                epochs: &::std::collections::BTreeSet<shekyl_types::SettlementEpoch>,
                floor: $crate::EpochFloor<$crate::Claimable>
            );
            (
                ::std::collections::BTreeMap<
                    shekyl_types::SettlementEpoch,
                    ::std::vec::Vec<shekyl_types::ShardId>,
                >
            );
            (persona, epochs, floor);
            (::std::collections::BTreeMap::new()));
        $crate::archival_reads!(@emit $policy; block_draws;
            (height: shekyl_types::BlockHeight);
            (::core::option::Option<shekyl_types::archival::BlockDraws>);
            (height);
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; drawable_digest;
            (
                epoch: shekyl_types::SettlementEpoch,
                floor: $crate::EpochFloor<$crate::Settling>
            );
            (::core::option::Option<shekyl_types::archival::DrawableDigest>);
            (epoch, floor);
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; complete_trees;
            (
                epoch: shekyl_types::SettlementEpoch,
                floor: $crate::EpochFloor<$crate::Claimable>
            );
            (::core::option::Option<shekyl_types::archival::CompleteTreeSet>);
            (epoch, floor);
            (::core::option::Option::None));
        $crate::archival_reads!(@emit $policy; release_journal_after;
            (height: shekyl_types::BlockHeight, floor: $crate::ReleaseJournalFloor);
            (::std::vec::Vec<shekyl_types::archival::ReleasedRecord>);
            (height, floor);
            (::std::vec::Vec::new()));
        $crate::archival_reads!(@emit $policy; slash_log_rows_after;
            (height: shekyl_types::BlockHeight, floor: $crate::SlashLogFloor);
            (::std::vec::Vec<shekyl_types::archival::LoggedSlash>);
            (height, floor);
            (::std::vec::Vec::new()));
    };
    (@emit {empty}; $name:ident; ($($params:tt)*); ($ok:ty); ($($arg:expr),*); ($empty:expr)) => {
        fn $name(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            $crate::archival_reads!(@touch $($arg),*);
            ::core::result::Result::Ok($empty)
        }
    };
    // Planted rows are values the close and the slash pass wrote. The
    // floor is the store's to compare, and a planted view keeps every row
    // it was given, so these arms `@touch` the floor and read their map.
    // A nested arm cannot name `self` (the note on `@methods`), so the
    // lookup stays here: `.copied()` for the `Copy` rows, `.cloned()` for
    // the set. `r_market`, `sigma_work`, `budget` and `complete_trees`
    // are those maps. `complete_trees` is not derived from `Σwork`: a
    // work total with no set is `Corrupt::CompleteTreesAbsent` (SI-31),
    // and an absent key stays `None`. `last_settled_slash_epoch` reads
    // its field. Every other archival read is `empty`'s.
    (@emit {planted $($price:ident).+ ; $($sigma:ident).+ ; $($budget:ident).+ ; $($trees:ident).+ ; $($mark:ident).+}; r_market; ($($params:tt)*); ($ok:ty); ($shard:expr, $epoch:expr, $floor:expr); ($empty:expr)) => {
        fn r_market(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            $crate::archival_reads!(@touch $floor);
            ::core::result::Result::Ok(self.$($price).+.get(&($shard, $epoch)).copied())
        }
    };
    (@emit {planted $($price:ident).+ ; $($sigma:ident).+ ; $($budget:ident).+ ; $($trees:ident).+ ; $($mark:ident).+}; sigma_work; ($($params:tt)*); ($ok:ty); ($epoch:expr, $floor:expr); ($empty:expr)) => {
        fn sigma_work(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            $crate::archival_reads!(@touch $floor);
            ::core::result::Result::Ok(self.$($sigma).+.get(&$epoch).copied())
        }
    };
    (@emit {planted $($price:ident).+ ; $($sigma:ident).+ ; $($budget:ident).+ ; $($trees:ident).+ ; $($mark:ident).+}; complete_trees; ($($params:tt)*); ($ok:ty); ($epoch:expr, $floor:expr); ($empty:expr)) => {
        fn complete_trees(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            $crate::archival_reads!(@touch $floor);
            ::core::result::Result::Ok(self.$($trees).+.get(&$epoch).cloned())
        }
    };
    (@emit {planted $($price:ident).+ ; $($sigma:ident).+ ; $($budget:ident).+ ; $($trees:ident).+ ; $($mark:ident).+}; budget; ($($params:tt)*); ($ok:ty); ($epoch:expr, $floor:expr); ($empty:expr)) => {
        fn budget(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            $crate::archival_reads!(@touch $floor);
            ::core::result::Result::Ok(self.$($budget).+.get(&$epoch).copied())
        }
    };
    (@emit {planted $($price:ident).+ ; $($sigma:ident).+ ; $($budget:ident).+ ; $($trees:ident).+ ; $($mark:ident).+}; last_settled_slash_epoch; ($($params:tt)*); ($ok:ty); ($($arg:expr),*); ($empty:expr)) => {
        fn last_settled_slash_epoch(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            ::core::result::Result::Ok(self.$($mark).+)
        }
    };
    (@emit {planted $($price:ident).+ ; $($sigma:ident).+ ; $($budget:ident).+ ; $($trees:ident).+ ; $($mark:ident).+}; $name:ident; ($($params:tt)*); ($ok:ty); ($($arg:expr),*); ($empty:expr)) => {
        fn $name(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            $crate::archival_reads!(@touch $($arg),*);
            ::core::result::Result::Ok($empty)
        }
    };
    (@emit {fault $err:expr}; $name:ident; ($($params:tt)*); ($ok:ty); ($($arg:expr),*); ($empty:expr)) => {
        fn $name(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            $crate::archival_reads!(@touch $($arg),*);
            ::core::result::Result::Err($err)
        }
    };
    (@emit {delegate $inner:ident}; $name:ident; ($($params:tt)*); ($ok:ty); ($($arg:expr),*); ($empty:expr)) => {
        fn $name(&self, $($params)*) -> ::core::result::Result<$ok, Self::Fault> {
            self.$inner.$name($($arg),*)
        }
    };
    (@touch) => {};
    (@touch $($arg:expr),+) => {
        let _ = ($($arg,)*);
    };
}
