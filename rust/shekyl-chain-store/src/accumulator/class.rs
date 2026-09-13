// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Accumulator-class vocabulary and the per-table freeze.
//!
//! The five tokens and the 49 assignments are the DRS-0 slice A freeze.
//! Prose lives in `docs/LMDB_WRITE_ATOMICITY_AUDIT.md` §10/§12; this module
//! is what DRS-E1 reads. Tests pin the two copies to each other.
//!
//! The 49 names are the `SHEKYL_LMDB_TABLES` spelling. A sibling module
//! that maps those tables (redb schema, codecs) must stay a bijection
//! with [`TABLE_CLASSES`].

use core::fmt;
use core::str::FromStr;

/// One of the five accumulator-class tokens (`DAEMON_REDB_STORE.md` §6.2,
/// audit §12).
///
/// A sixth token is unrepresentable. The schema-coverage gate still
/// asserts **classhood** (every table carries one token) rather than
/// soundness (the assignment is reversible); that limitation is
/// unchanged. This enum is the vocabulary the assignment is written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccumulatorClass {
    /// Order-independent XOR fold. Pop-symmetric by construction,
    /// conditional on the per-table write contract.
    SetShaped,
    /// Running chained hash. Pop-symmetric by checkpoint, not by
    /// construction.
    AppendMostly,
    /// Full-domain digest every block. Cheap because the domain is bounded.
    Small,
    /// Recompute from a named source through an independently specified
    /// derivation.
    Derived,
    /// Not folded, with a named reason (non-chain / node-local / dead).
    Excluded,
}

impl AccumulatorClass {
    /// The five tokens, in the order §12's table states them.
    pub const ALL: [Self; 5] = [
        Self::SetShaped,
        Self::AppendMostly,
        Self::Small,
        Self::Derived,
        Self::Excluded,
    ];

    /// Markdown token written in the audit coverage matrix.
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::SetShaped => "set-shaped",
            Self::AppendMostly => "append-mostly",
            Self::Small => "small",
            Self::Derived => "derived",
            Self::Excluded => "excluded",
        }
    }

    /// Parse a matrix token. Unknown strings are `None`, not a default.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "set-shaped" => Some(Self::SetShaped),
            "append-mostly" => Some(Self::AppendMostly),
            "small" => Some(Self::Small),
            "derived" => Some(Self::Derived),
            "excluded" => Some(Self::Excluded),
            _ => None,
        }
    }
}

impl fmt::Display for AccumulatorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_token())
    }
}

impl FromStr for AccumulatorClass {
    type Err = UnknownAccumulatorClass;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_token(s).ok_or(UnknownAccumulatorClass)
    }
}

/// A string that is not one of the five freeze tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownAccumulatorClass;

impl fmt::Display for UnknownAccumulatorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown accumulator class token")
    }
}

impl core::error::Error for UnknownAccumulatorClass {}

/// Per-table freeze: one class per declared LMDB table, alphabetical,
/// matching the audit §10 matrix. DRS-E1 looks up by name.
pub const TABLE_CLASSES: &[(&str, AccumulatorClass)] = &[
    ("alt_blocks", AccumulatorClass::Excluded),
    (
        "archival_alt_attestation_witness",
        AccumulatorClass::Excluded,
    ),
    ("archival_attestation_witness", AccumulatorClass::Small),
    ("archival_bond", AccumulatorClass::SetShaped),
    (
        "archival_bond_holdings_update_log",
        AccumulatorClass::AppendMostly,
    ),
    ("archival_bond_rebond_log", AccumulatorClass::AppendMostly),
    ("archival_bond_unbond_log", AccumulatorClass::AppendMostly),
    ("archival_budget", AccumulatorClass::Small),
    ("archival_budget_accrual", AccumulatorClass::Small),
    (
        "archival_emission_claim_log",
        AccumulatorClass::AppendMostly,
    ),
    ("archival_epoch_close_log", AccumulatorClass::AppendMostly),
    ("archival_r_market", AccumulatorClass::Small),
    ("archival_serve_credit", AccumulatorClass::Small),
    ("archival_settlement", AccumulatorClass::Small),
    ("archival_shard_segment", AccumulatorClass::SetShaped),
    ("archival_sigma_work", AccumulatorClass::Small),
    ("archival_slash_applied", AccumulatorClass::SetShaped),
    ("archival_slash_log", AccumulatorClass::AppendMostly),
    ("block_burn", AccumulatorClass::SetShaped),
    ("block_heights", AccumulatorClass::SetShaped),
    ("block_info", AccumulatorClass::AppendMostly),
    ("block_pending_additions", AccumulatorClass::SetShaped),
    ("blocks", AccumulatorClass::AppendMostly),
    ("curve_tree_checkpoints", AccumulatorClass::Derived),
    ("curve_tree_layers", AccumulatorClass::Derived),
    ("curve_tree_leaves", AccumulatorClass::AppendMostly),
    ("curve_tree_meta", AccumulatorClass::Small),
    ("curve_tree_roots", AccumulatorClass::SetShaped),
    ("hf_starting_heights", AccumulatorClass::Excluded),
    ("hf_versions", AccumulatorClass::Small),
    ("leaf_to_output", AccumulatorClass::SetShaped),
    ("output_amounts", AccumulatorClass::SetShaped),
    ("output_metadata", AccumulatorClass::Excluded),
    ("output_to_leaf", AccumulatorClass::SetShaped),
    ("output_txs", AccumulatorClass::SetShaped),
    ("pending_tree_drain", AccumulatorClass::SetShaped),
    ("pending_tree_leaves", AccumulatorClass::SetShaped),
    ("properties", AccumulatorClass::Small),
    ("spent_keys", AccumulatorClass::SetShaped),
    ("tx_indices", AccumulatorClass::SetShaped),
    ("tx_outputs", AccumulatorClass::AppendMostly),
    ("txpool_blob", AccumulatorClass::Excluded),
    ("txpool_meta", AccumulatorClass::Excluded),
    ("txs", AccumulatorClass::Excluded),
    ("txs_pqc_auths", AccumulatorClass::AppendMostly),
    ("txs_prunable", AccumulatorClass::Excluded),
    ("txs_prunable_hash", AccumulatorClass::AppendMostly),
    ("txs_prunable_tip", AccumulatorClass::Excluded),
    ("txs_pruned", AccumulatorClass::AppendMostly),
];

/// Class assigned to `name`, or `None` if `name` is not a declared table.
#[must_use]
pub fn class_for_table(name: &str) -> Option<AccumulatorClass> {
    TABLE_CLASSES
        .binary_search_by_key(&name, |(n, _)| *n)
        .ok()
        .map(|i| TABLE_CLASSES[i].1)
}

/// How a set-shaped table's C++ delete path exposes the stored element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetShapedDelete {
    /// The delete path already holds the value (cursor positioned on the
    /// row, or an explicit `mdb_get` + verify).
    ValueInHand,
    /// `mdb_del(txn, dbi, key, nullptr)` — the value is never read. The
    /// Rust store must perform a read the C++ does not.
    KeyAlone,
}

/// How a set-shaped table's C++ write path treats an existing row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetShapedInsert {
    /// Written through `m_wcursors` with `mdb_cursor_put`. No flags-0
    /// `mdb_put`.
    CursorManaged,
    /// Every write is `mdb_put(..., 0)`. An XOR fold must read-modify-write.
    BlindUpsert,
    /// At least one flags-0 put **and** at least one insert-only put
    /// (`MDB_NOOVERWRITE`). A single table-level hook is wrong on one of
    /// the two paths; the Rust store hooks the call sites.
    MixedOverwrite,
}

/// Write-path contract for one set-shaped table.
///
/// Where C++ does not have the stored element in hand, a port that
/// transliterates `mdb_del`/`mdb_put` into a bare redb `remove`/`insert`
/// desynchronizes the accumulator. That is the instruction.
///
/// A sound engine may over-approximate to "read before every set-shaped
/// mutation" and ignore [`needs_read_before_delete`](Self::needs_read_before_delete)
/// / [`needs_read_modify_write`](Self::needs_read_modify_write) as filters.
/// Extra reads are free relative to a missed one. The one row that
/// over-approximation does **not** cover is
/// [`SetShapedInsert::MixedOverwrite`]: a single table-level hook is
/// wrong on one of that table's two write sites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetShapedContract {
    /// LMDB table name (`SHEKYL_LMDB_TABLES` spelling).
    pub name: &'static str,
    /// Delete-path exposure of the stored element.
    pub delete: SetShapedDelete,
    /// Insert/overwrite semantics.
    pub insert: SetShapedInsert,
}

impl SetShapedContract {
    /// Lookup by LMDB name.
    #[must_use]
    pub fn for_table(name: &str) -> Option<Self> {
        SET_SHAPED_CONTRACTS
            .iter()
            .copied()
            .find(|c| c.name == name)
    }

    /// The Rust store must read before delete.
    #[must_use]
    pub const fn needs_read_before_delete(self) -> bool {
        matches!(self.delete, SetShapedDelete::KeyAlone)
    }

    /// The Rust store must fold the old value out before folding the new
    /// one in. True for both [`SetShapedInsert::BlindUpsert`] and
    /// [`SetShapedInsert::MixedOverwrite`] — the latter still has a
    /// flags-0 path.
    #[must_use]
    pub const fn needs_read_modify_write(self) -> bool {
        matches!(
            self.insert,
            SetShapedInsert::BlindUpsert | SetShapedInsert::MixedOverwrite
        )
    }

    /// Accumulator hook belongs on the write *site*, not the table.
    #[must_use]
    pub const fn hook_is_per_call_site(self) -> bool {
        matches!(self.insert, SetShapedInsert::MixedOverwrite)
    }
}

/// All fifteen set-shaped tables, alphabetical. Keep in bijection with
/// the `SetShaped` rows of [`TABLE_CLASSES`].
pub const SET_SHAPED_CONTRACTS: &[SetShapedContract] = &[
    SetShapedContract {
        name: "archival_bond",
        delete: SetShapedDelete::KeyAlone,
        insert: SetShapedInsert::BlindUpsert,
    },
    SetShapedContract {
        name: "archival_shard_segment",
        delete: SetShapedDelete::ValueInHand,
        insert: SetShapedInsert::MixedOverwrite,
    },
    SetShapedContract {
        name: "archival_slash_applied",
        delete: SetShapedDelete::KeyAlone,
        insert: SetShapedInsert::BlindUpsert,
    },
    SetShapedContract {
        name: "block_burn",
        delete: SetShapedDelete::KeyAlone,
        insert: SetShapedInsert::BlindUpsert,
    },
    SetShapedContract {
        name: "block_heights",
        delete: SetShapedDelete::ValueInHand,
        insert: SetShapedInsert::CursorManaged,
    },
    SetShapedContract {
        name: "block_pending_additions",
        delete: SetShapedDelete::ValueInHand,
        insert: SetShapedInsert::BlindUpsert,
    },
    SetShapedContract {
        name: "curve_tree_roots",
        delete: SetShapedDelete::KeyAlone,
        insert: SetShapedInsert::BlindUpsert,
    },
    SetShapedContract {
        name: "leaf_to_output",
        delete: SetShapedDelete::KeyAlone,
        insert: SetShapedInsert::BlindUpsert,
    },
    SetShapedContract {
        name: "output_amounts",
        delete: SetShapedDelete::ValueInHand,
        insert: SetShapedInsert::CursorManaged,
    },
    SetShapedContract {
        name: "output_to_leaf",
        delete: SetShapedDelete::ValueInHand,
        insert: SetShapedInsert::BlindUpsert,
    },
    SetShapedContract {
        name: "output_txs",
        delete: SetShapedDelete::ValueInHand,
        insert: SetShapedInsert::CursorManaged,
    },
    SetShapedContract {
        name: "pending_tree_drain",
        delete: SetShapedDelete::ValueInHand,
        insert: SetShapedInsert::BlindUpsert,
    },
    SetShapedContract {
        name: "pending_tree_leaves",
        delete: SetShapedDelete::KeyAlone,
        insert: SetShapedInsert::BlindUpsert,
    },
    SetShapedContract {
        name: "spent_keys",
        delete: SetShapedDelete::ValueInHand,
        insert: SetShapedInsert::CursorManaged,
    },
    SetShapedContract {
        name: "tx_indices",
        delete: SetShapedDelete::ValueInHand,
        insert: SetShapedInsert::CursorManaged,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    const AUDIT: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/LMDB_WRITE_ATOMICITY_AUDIT.md"
    ));

    fn backtick_names(cell: &str) -> Vec<&str> {
        let mut names = Vec::new();
        let mut rest = cell;
        while let Some(start) = rest.find('`') {
            rest = &rest[start + 1..];
            let Some(end) = rest.find('`') else {
                break;
            };
            let name = &rest[..end];
            if name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                && !name.is_empty()
            {
                names.push(name);
            }
            rest = &rest[end + 1..];
        }
        names
    }

    fn matrix_class_rows(audit: &str) -> Vec<(&str, AccumulatorClass)> {
        let start = audit
            .find("## 10. Coverage matrix")
            .expect("audit §10 is missing");
        let rest = &audit[start..];
        let end = rest.find("\n## 11.").expect("audit §11 is missing");
        let matrix = &rest[..end];
        let mut rows = Vec::new();
        for line in matrix.lines() {
            if !line.starts_with("| `") {
                continue;
            }
            let cells: Vec<&str> = line
                .split('|')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            assert_eq!(
                cells.len(),
                5,
                "coverage row must have 5 cells, got {cells:?}"
            );
            let name = cells[0]
                .strip_prefix('`')
                .and_then(|s| s.strip_suffix('`'))
                .expect("table name is backtick-quoted");
            let class = AccumulatorClass::from_token(cells[4])
                .unwrap_or_else(|| panic!("unknown class token on {name}: {}", cells[4]));
            rows.push((name, class));
        }
        rows
    }

    fn falsifier_sets(audit: &str) -> (Vec<&str>, Vec<&str>, Vec<&str>) {
        let start = audit
            .find("### The per-table falsifier")
            .expect("falsifier subsection is missing");
        let rest = &audit[start..];
        // `rest` starts at this heading; the next `\n### ` is the following one.
        let section_end = rest[1..]
            .find("\n### ")
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        let section = &rest[..section_end];
        let mut listed = Vec::new();
        let mut delete_alone = Vec::new();
        let mut blind = Vec::new();
        for line in section.lines() {
            if !line.starts_with('|')
                || line.contains("Delete has the element")
                || line.contains("---")
            {
                continue;
            }
            let cells: Vec<&str> = line
                .split('|')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if cells.len() != 3 {
                continue;
            }
            let names = backtick_names(cells[0]);
            if names.is_empty() {
                continue;
            }
            let delete_has = cells[1].to_ascii_lowercase().contains("yes");
            let is_blind = cells[2].to_ascii_lowercase().contains("yes");
            for n in &names {
                listed.push(*n);
                if !delete_has {
                    delete_alone.push(*n);
                }
                if is_blind {
                    blind.push(*n);
                }
            }
        }
        (listed, delete_alone, blind)
    }

    #[test]
    fn table_classes_is_sorted_and_unique() {
        for pair in TABLE_CLASSES.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "TABLE_CLASSES must be strictly sorted: {} !< {}",
                pair[0].0,
                pair[1].0
            );
        }
    }

    #[test]
    fn every_set_shaped_row_has_a_write_contract_and_conversely() {
        let classed: Vec<&str> = TABLE_CLASSES
            .iter()
            .filter(|(_, c)| *c == AccumulatorClass::SetShaped)
            .map(|(n, _)| *n)
            .collect();
        let contracted: Vec<&str> = SET_SHAPED_CONTRACTS.iter().map(|c| c.name).collect();
        assert_eq!(classed, contracted);
    }

    #[test]
    fn class_for_table_hits_every_row_and_misses_unknown() {
        for (name, class) in TABLE_CLASSES {
            assert_eq!(class_for_table(name), Some(*class));
        }
        assert_eq!(class_for_table("not_a_table"), None);
    }

    #[test]
    fn unknown_token_does_not_default() {
        assert_eq!(AccumulatorClass::from_token("torn-commit"), None);
        assert!("torn-commit".parse::<AccumulatorClass>().is_err());
    }

    #[test]
    fn table_classes_match_the_audit_matrix() {
        let audit_rows = matrix_class_rows(AUDIT);
        let rust_rows: Vec<(&str, AccumulatorClass)> = TABLE_CLASSES.to_vec();
        assert_eq!(
            audit_rows, rust_rows,
            "TABLE_CLASSES drifted from audit §10 Accumulator class column"
        );
    }

    #[test]
    fn set_shaped_contracts_match_the_audit_falsifier_sets() {
        let (listed, delete_alone, blind) = falsifier_sets(AUDIT);
        let contracted: Vec<&str> = SET_SHAPED_CONTRACTS.iter().map(|c| c.name).collect();
        let mut listed_sorted = listed.clone();
        listed_sorted.sort_unstable();
        listed_sorted.dedup();
        assert_eq!(
            listed_sorted, contracted,
            "falsifier table names drifted from SET_SHAPED_CONTRACTS"
        );

        let rust_alone: Vec<&str> = SET_SHAPED_CONTRACTS
            .iter()
            .filter(|c| c.needs_read_before_delete())
            .map(|c| c.name)
            .collect();
        let mut audit_alone = delete_alone;
        audit_alone.sort_unstable();
        assert_eq!(audit_alone, rust_alone);

        let rust_blind: Vec<&str> = SET_SHAPED_CONTRACTS
            .iter()
            .filter(|c| c.needs_read_modify_write())
            .map(|c| c.name)
            .collect();
        let mut audit_blind = blind;
        audit_blind.sort_unstable();
        assert_eq!(audit_blind, rust_blind);
    }

    #[test]
    fn only_archival_shard_segment_is_mixed_overwrite() {
        let mixed: Vec<&str> = SET_SHAPED_CONTRACTS
            .iter()
            .filter(|c| c.hook_is_per_call_site())
            .map(|c| c.name)
            .collect();
        assert_eq!(mixed, ["archival_shard_segment"]);
    }

    #[test]
    fn five_tokens_round_trip() {
        for class in AccumulatorClass::ALL {
            assert_eq!(AccumulatorClass::from_token(class.as_token()), Some(class));
            assert_eq!(class.to_string(), class.as_token());
        }
    }
}
