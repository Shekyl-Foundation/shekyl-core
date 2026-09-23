// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The wire twin held to `tx_form`, site by site (`CHAIN_RULES_SLICE_5.md`
//! §3.1, Q1 ruled (a), commit 8).
//!
//! `shekyl_wire::Transaction::validate` is a second Rust implementation of
//! roughly fourteen consensus predicates, written for the wallet and
//! reconciled with nothing: a transaction one copy accepts and the other
//! refuses was undetectable. Q1 made `tx_form` the rule of record and
//! demoted the twin to a conformance-tested pre-check. This module is the
//! test — **enumerated, not sampled**: every `Err(` site in
//! `shekyl-wire/src/transaction.rs` is a row of [`SITES`], classified, and
//! the table's shape is checked against the file itself (`include_str!`),
//! so an arm cannot arrive unclassified.
//!
//! # Four arms, not three
//!
//! R8's discriminator — *would this still be required if the consensus rules
//! changed?* — sorts **parse** (a blob this refuses cannot be judged under
//! any rule set) from **rule** (consensus content, keyed to its census row).
//! Some sites are neither: writer-side construction guards, an arm no input
//! can reach, a typed conversion's failure — the **invariant** arm, so an
//! assertion-shaped site is never forced into the nearer bucket and keyed to
//! a row that does not exist. One site is a fourth thing: the twin refuses on
//! `MAX_TX_EXTRA`, which the census carries as **policy** (`CEN-M4`, relay
//! cap; *"consensus side has no tx_extra bound beyond CEN-H1"*). The crate
//! keeps policy rows in their own enum precisely so one is never counted as
//! consensus; forcing it into `Rule` would be the mis-keying the third arm
//! exists to prevent, so it has its own. The count is reported as four
//! numbers, pinned.
//!
//! # What each arm is held to
//!
//! - A **rule** arm with an in-memory face carries the transaction that trips
//!   **it** (the twin's message is matched, so an earlier arm firing first
//!   is a test failure, not a pass), and then `tx_form` — or `validate` for a
//!   coinbase — is held to the census row **by the row's registry status**:
//!   implemented → refused on that row; by construction → the tripping value
//!   does not round-trip the wire; pending → nothing yet, and the day the
//!   row flips the implemented branch runs, so the assertion **arms itself**
//!   with no pin to update. A recorded **divergence** is the exception, and
//!   says what `tx_form` does instead.
//! - A **rule** arm with a read-only face (a parser arm) has no tripping
//!   value — the typed input cannot express it. It must either be a row the
//!   registry holds `by_construction`, or have an in-memory twin in this
//!   table keyed to the same row. Checked.
//! - **Parse** and **invariant** arms are counted and named; nothing runs.
//!
//! The baseline — a coinbase, a two-output spend, a serve-credit — passes
//! **both** the twin and the crate. That is the positive witness; every trip
//! is one mutation of it.

use crate::block::Candidate;
use crate::census::{CenRow, PolicyRow, RowStatus};
use crate::fault::FormAttempt;
use crate::harness::fixture::{
    bp_plus_layout_for, candidate_on, coinbase, listed, point, pqc_auth_filler, recorded, root,
    serve_credit_only, G, TWO_G,
};
use crate::harness::{assert_refused, expected_seed, judged, Faulted, MockChain, MockSubstrate};
use crate::rule_set::RuleSet;
use crate::trust::Trust;
use crate::validate::{form, tx_form, validate};
use crate::verdict::{ChainValid, Locus, TxSlot, Verdict};
use shekyl_wire::transaction::{
    MAX_TX_EXTRA, MAX_TX_SIZE, PQC_HYBRID_SINGLE_KEY_LEN, PQC_MAX_PUBLIC_KEY_BLOB,
    TAG_INPUT_SERVE_CREDIT, UNLOCK_TIME_BLOCK_SENTINEL,
};
use shekyl_wire::tx_extra::{self, conforming_pqc_leaf_blob, TxExtraField, HYBRID_KEM_CT_BYTES};
use shekyl_wire::{BondPost, BondPostKind, Ct, Holdings, Input, Output, Transaction};

/// The twin's source, read at compile time: the table below is checked
/// against it, not against a remembered count.
const TWIN_SOURCE: &str = include_str!("../../../shekyl-wire/src/transaction.rs");

// ---- the classification -------------------------------------------------

/// R8's discriminator, with the two arms it does not sort, and the one the
/// registry sorts differently.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Arm {
    /// Would survive any consensus-rule change: a cap before an allocation, a
    /// tag with no decoding, an encoding that is not canonical. Counted;
    /// nothing runs.
    Parse,
    /// Consensus content, keyed to the census row of record.
    Rule(CenRow),
    /// Relay / pool policy the twin enforces as if it were consensus. Keyed
    /// to the policy row; the divergence is recorded, not asserted away.
    Policy(PolicyRow),
    /// Neither: a construction guard on the writer or the in-memory value, an
    /// arm no input can reach, a typed conversion's failure. Counted; nothing
    /// runs. Each says in its note why it is not a rule.
    Invariant,
}

/// Where the arm sits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Face {
    /// In a `read` path — bytes to value. The typed input cannot express
    /// what it refuses.
    Read,
    /// In `validate` / `validate_context_free_pruned` — on the value.
    Memory,
    /// A helper both paths call.
    Both,
}

/// What `tx_form` (or `validate`, for a coinbase) is held to once the twin
/// has refused the tripping transaction on this arm.
#[derive(Clone, Copy, Debug)]
enum Expect {
    /// Read the row's registry status and hold the crate to it — the
    /// self-arming form (see the module doc).
    FromRegistry,
    /// The two copies disagree here, and the disagreement is the finding:
    /// the twin refuses, the crate does `outcome`. `note` names the owner.
    Diverges {
        note: &'static str,
        outcome: Outcome,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Outcome {
    /// `tx_form` accepts the transaction the twin refused.
    Accepted,
    /// `tx_form` refuses it, on this other row.
    RefusedOn(CenRow),
}

/// The transaction that trips the arm and nothing before it in the twin.
#[derive(Clone, Copy)]
enum Trip {
    /// No tripping value: parse and invariant arms, and read-face rule arms.
    None,
    /// A non-coinbase transaction, judged at the pool's slot.
    Lone(fn() -> Transaction, Expect),
    /// A mutation of the fixture coinbase, judged through `form` and
    /// `validate` on a one-block chain (so genesis exemptions do not apply).
    Coinbase(fn(&mut Transaction), Expect),
}

struct Site {
    /// A literal fragment of the arm's message — the site's identity in the
    /// source, and what the twin's refusal is matched against.
    fragment: &'static str,
    face: Face,
    arm: Arm,
    trip: Trip,
    /// Why the arm is classified as it is, where that is not obvious from
    /// the row.
    note: &'static str,
}

const fn parse(fragment: &'static str, face: Face, note: &'static str) -> Site {
    Site {
        fragment,
        face,
        arm: Arm::Parse,
        trip: Trip::None,
        note,
    }
}

const fn invariant(fragment: &'static str, face: Face, note: &'static str) -> Site {
    Site {
        fragment,
        face,
        arm: Arm::Invariant,
        trip: Trip::None,
        note,
    }
}

const fn read_rule(fragment: &'static str, row: CenRow, note: &'static str) -> Site {
    Site {
        fragment,
        face: Face::Read,
        arm: Arm::Rule(row),
        trip: Trip::None,
        note,
    }
}

const fn rule(
    fragment: &'static str,
    face: Face,
    row: CenRow,
    trip: fn() -> Transaction,
    note: &'static str,
) -> Site {
    Site {
        fragment,
        face,
        arm: Arm::Rule(row),
        trip: Trip::Lone(trip, Expect::FromRegistry),
        note,
    }
}

const fn coinbase_rule(
    fragment: &'static str,
    row: CenRow,
    trip: fn(&mut Transaction),
    note: &'static str,
) -> Site {
    Site {
        fragment,
        face: Face::Memory,
        arm: Arm::Rule(row),
        trip: Trip::Coinbase(trip, Expect::FromRegistry),
        note,
    }
}

const fn diverges(
    fragment: &'static str,
    arm: Arm,
    trip: fn() -> Transaction,
    outcome: Outcome,
    note: &'static str,
) -> Site {
    Site {
        fragment,
        face: Face::Memory,
        arm,
        trip: Trip::Lone(trip, Expect::Diverges { note, outcome }),
        note,
    }
}

/// Every `Err(` site in `shekyl-wire/src/transaction.rs`, in file order.
/// The count is checked against the file; a new arm fails the shape test
/// until it has a row here.
const SITES: &[Site] = &[
    // -- helpers and `read` ------------------------------------------------
    parse(
        "length {len} exceeds cap {max}",
        Face::Read,
        "read_len_prefixed_bounded: a declared length refused before the allocation",
    ),
    parse(
        "length {len} != canonical {expected}",
        Face::Read,
        "read_len_prefixed_exact: a fixed-size encoding that is not its size is malformed",
    ),
    parse(
        "emission canonical_bytes length {} outside",
        Face::Both,
        "a transport ceiling on an opaque blob (the wire's own doc: the C++ transport cap verbatim); the interior is 4.J's",
    ),
    parse(
        "emission canonical_bytes leading byte",
        Face::Both,
        "the blob echoes the wire tag it was read under — codec, not rule",
    ),
    parse(
        "key_offsets count {n_offsets} exceeds parse cap",
        Face::Read,
        "READ_LEN_CAP before the allocation; the offsets' emptiness is I6's, below",
    ),
    read_rule(
        "unsupported input tag",
        CenRow::H5,
        "the input-variant whitelist's byte face; the `gen`-outside-coinbase half is the in-memory arm keyed here too",
    ),
    parse(
        "holdings shard count {count} exceeds",
        Face::Read,
        "a mirror of the retention codec's `ShardSet::new` bound (`bond_wire.rs`), which is that crate's own gate — no census row names it; the wire copies the codec so two decoders cannot diverge",
    ),
    parse(
        "holdings shard id {} appears more than once",
        Face::Read,
        "as above: `ShardSet::new`'s duplicate-freeness, mirrored",
    ),
    parse(
        "invalid holdings kind",
        Face::Read,
        "an unknown discriminant has no decoding",
    ),
    parse(
        "serve_credit canonical_bytes length {} outside",
        Face::Both,
        "a transport ceiling (`ARCHIVAL_SERVE_CREDIT_VIN_MAX_BYTES`); CEN-J1 says only the Rust codec parses the interior",
    ),
    parse(
        "serve_credit canonical_bytes leading byte",
        Face::Both,
        "the tag echo, as for the emission blob",
    ),
    rule(
        "serve_credit pruned record length {} outside",
        Face::Both,
        CenRow::J2,
        j2_empty_pass_record,
        "CEN-J2 names the bound: one pruned pass record per vin, each within `SERVE_CREDIT_PRUNED_MAX_BYTES`",
    ),
    invariant(
        "BondPostKind::Other must not use the JoinMarket tag \\",
        Face::Read,
        "`write`'s guard against emitting a blob `read` would mis-parse: a construction the wire cannot carry, refused at the writer",
    ),
    rule(
        "bond_post hybrid_public_key {} != canonical",
        Face::Both,
        CenRow::J11,
        j11_short_hybrid_key,
        "CEN-J11: hybrid pubkey length canonical",
    ),
    rule(
        "bond_post bond_spend_pk {} != canonical",
        Face::Both,
        CenRow::J12,
        j12_short_bond_spend_pk,
        "CEN-J12: JoinMarket commits a canonical-length `bond_spend_pk`",
    ),
    invariant(
        "BondPostKind::Other must not use the JoinMarket tag\"",
        Face::Memory,
        "the in-memory face of the writer's guard: `Other(JOINMARKET_TAG)` is a misconstruction, not a rule violation",
    ),
    parse(
        "bond_post holdings shard count {} exceeds",
        Face::Memory,
        "the in-memory face of the `ShardSet::new` mirror",
    ),
    read_rule(
        "unsupported output tag",
        CenRow::H12,
        "one output tag exists; `Output` has one shape — the registry holds H12 by construction on it",
    ),
    parse(
        "trailing bytes after Bp+ blob",
        Face::Read,
        "exact consumption of a standalone BP+ blob (`BpPlus::from_bytes`, the tx-builder's path)",
    ),
    read_rule(
        "Bp+ |L| {l_len} outside consensus range",
        CenRow::H19,
        "the layout's byte face; the exact per-output coupling is the in-memory arm",
    ),
    read_rule(
        "Bp+ |R| {r_len} != |L|",
        CenRow::H19,
        "as above",
    ),
    parse(
        "nbp {nbp} exceeds parse cap",
        Face::Read,
        "READ_LEN_CAP before the allocation; `nbp == 1` is H19's, below",
    ),
    read_rule(
        "unsupported ct type",
        CenRow::H15,
        "`Ct` has two arms; the Null-outside-coinbase half is the in-memory arm keyed here too",
    ),
    parse(
        "input count {n_inputs} exceeds parse cap",
        Face::Read,
        "READ_LEN_CAP; the consensus input cap is I4's, below",
    ),
    read_rule(
        "output count {n_outputs} exceeds {MAX_OUTPUTS}",
        CenRow::H19,
        "`BULLETPROOF_PLUS_MAX_OUTPUTS`: the C++ refuses it as the BP+ max-amounts clause (`ct_types.cpp:245`), which the census carries under H19",
    ),
    read_rule(
        "transaction version {version} != {TX_VERSION}",
        CenRow::H2,
        "one version parses; H2 (and H13, the same property's third site) hold by construction",
    ),
    read_rule(
        "tx blob {} exceeds {MAX_TX_SIZE}",
        CenRow::H1,
        "the size cap before the parse; the in-memory arm is keyed here too",
    ),
    read_rule(
        "trailing byte(s) after transaction",
        CenRow::H23,
        "exact consumption: a blob that does not parse cleanly is not a transaction — H23's byte face, by construction",
    ),
    // -- `validate_context_free_pruned` --------------------------------------
    rule(
        "transaction has no inputs",
        Face::Memory,
        CenRow::H4,
        h4_no_inputs,
        "",
    ),
    rule(
        "output count {n_out} exceeds {MAX_OUTPUTS}",
        Face::Memory,
        CenRow::H19,
        h19_seventeen_outputs,
        "the in-memory face of the max-amounts clause",
    ),
    rule(
        "gen input must be the sole input",
        Face::Memory,
        CenRow::H5,
        h5_gen_beside_a_spend,
        "",
    ),
    rule(
        "serve_credit must not mix with other input arms",
        Face::Memory,
        CenRow::H6,
        h6_serve_credit_beside_a_spend,
        "",
    ),
    rule(
        "serve_credit tx must be fee-only",
        Face::Memory,
        CenRow::H20,
        h20_serve_credit_with_an_auth,
        "",
    ),
    rule(
        "at most one bond_post input per tx",
        Face::Memory,
        CenRow::H6,
        h6_two_bond_posts,
        "",
    ),
    rule(
        "at most one emission input per tx",
        Face::Memory,
        CenRow::H6,
        h6_two_emissions,
        "",
    ),
    rule(
        "emission must not mix with a bond_post input",
        Face::Memory,
        CenRow::H6,
        h6_emission_beside_a_bond_post,
        "",
    ),
    diverges(
        "tx_extra {} exceeds {MAX_TX_EXTRA}",
        Arm::Policy(PolicyRow::M4),
        m4_extra_over_the_relay_cap,
        Outcome::Accepted,
        "CEN-M4 is a relay cap (tx_pool.cpp), flagged P: `consensus side has no tx_extra bound beyond CEN-H1`. The twin refuses what consensus accepts; a wallet pre-check may, and the census row it answers to is the policy one",
    ),
    rule(
        "tx size {size} exceeds {MAX_TX_SIZE}",
        Face::Memory,
        CenRow::H1,
        h1_a_megabyte_proof,
        "",
    ),
    rule(
        "unlock_time {} is the timestamp form",
        Face::Memory,
        CenRow::H16,
        h16_the_sentinel,
        "",
    ),
    rule(
        "inputs exceed {MAX_FCMP_INPUTS}",
        Face::Memory,
        CenRow::I4,
        i4_nine_inputs,
        "",
    ),
    rule(
        "spend input has non-empty key_offsets",
        Face::Memory,
        CenRow::I6,
        i6_offsets,
        "the arm CEN-H24's falsifier waits on: when I6 lands, this row asserts the crate refuses the offsets fixture",
    ),
    rule(
        "key images not strictly descending",
        Face::Memory,
        CenRow::I5,
        i5_ascending_key_images,
        "I5 subsumes H10 (a repeat is not descending); the twin has the one arm, keyed to it",
    ),
    rule(
        "Null ct is coinbase-only",
        Face::Memory,
        CenRow::H15,
        h15_null_ct_on_a_spend,
        "",
    ),
    coinbase_rule(
        "coinbase has no outputs",
        CenRow::F4,
        f4_no_outputs,
        "F4: exactly one output above genesis; the twin holds the lower edge at every height",
    ),
    coinbase_rule(
        "coinbase must carry a Null ct, not Fcmp",
        CenRow::F3,
        f3_fcmp_ct,
        "",
    ),
    rule(
        "pqc_auth public key {} exceeds",
        Face::Memory,
        CenRow::I16,
        i16_oversized_key_blob,
        "CEN-I16 names `PQC_MAX_PUBLIC_KEY_BLOB` as the multisig blob's upper bound",
    ),
    parse(
        "pqc_auth signature {} exceeds",
        Face::Memory,
        "a DoS ceiling (the wire's doc: `DECOUPLED from MAX — correctness is the exact-length parse in crypto-pq`); no census row names a signature-blob bound",
    ),
    rule(
        "ct base arrays (enc_amounts=",
        Face::Memory,
        CenRow::H8,
        h8_short_base_arrays,
        "H8 holds by construction on the wire: the tripping value does not round-trip",
    ),
    rule(
        "spend has {n_out} output(s), needs >= 2",
        Face::Memory,
        CenRow::I1,
        i1_one_output_spend,
        "",
    ),
    // -- `validate` (prunable-coupled) ----------------------------------------
    rule(
        "spend/bond_post has {n_out} output(s), needs >= 2",
        Face::Memory,
        CenRow::I1,
        i1_one_output_bond_post,
        "the bond-post face of I1 (`non-serve-credit txs`)",
    ),
    rule(
        "pqc_auths {} != input count {n_in}",
        Face::Memory,
        CenRow::I8,
        i8_no_auths,
        "",
    ),
    rule(
        "nbp {} != 1",
        Face::Memory,
        CenRow::H19,
        h19_no_proof,
        "",
    ),
    rule(
        "Bp+ |L|/|R| ({}/{}) != {expected_lr}",
        Face::Memory,
        CenRow::H19,
        h19_layout_for_the_wrong_output_count,
        "",
    ),
    rule(
        "pseudoOuts {} != spend (ToKey) input count",
        Face::Memory,
        CenRow::I9,
        i9_no_pseudo_outs,
        "",
    ),
    diverges(
        "fee-only ct (no prunable) must have no",
        Arm::Rule(CenRow::H20),
        pruned_form_bond_post_with_an_output,
        Outcome::RefusedOn(CenRow::H21),
        "the twin's fee-only arm asserts H20's shape on ANY `prunable: None` transaction. For a serve-credit the shape arm above fires first, so this one is reachable only by a `prunable: None` non-serve-credit — the storage-pruned form, which the C++ has no value for (its prunable is always a struct) and which `Option<Prunable>` admits (FOLLOWUPS: `Transaction::full/pruned`). The crate classifies by the vin and refuses the same value on its own row",
    ),
    diverges(
        "fee-only ct (no prunable) must carry empty",
        Arm::Rule(CenRow::H20),
        pruned_form_bond_post_with_an_auth,
        Outcome::RefusedOn(CenRow::H21),
        "as above",
    ),
    invariant(
        "key-image input(s) but no prunable proof",
        Face::Memory,
        "unreachable: a key image forces `n_out >= 2` at the context-free `spend has … needs >= 2` arm, and `n_out != 0` fires the `must have no outputs` arm before this one. The proof's non-emptiness is CEN-I14's, held elsewhere",
    ),
    invariant(
        "return Err(PrunedError);",
        Face::Memory,
        "`into_full`'s typed boundary: a serve-credit has no spend proof to promote. A conversion's failure, not a refusal",
    ),
    invariant(
        "_ => Err(PrunedError),",
        Face::Memory,
        "`into_full`: no prunable spend-proof to promote (coinbase, storage-pruned)",
    ),
];

// ---- the baseline ---------------------------------------------------------

/// `tx` with the `extra` CEN-I19 requires for its output count: one `0x06`
/// of `1120·n` and one `0x07` of `64·n` conforming leaf entries — what the
/// twin's `validate` demands of every transaction, and what the crate's
/// fixtures do not carry (I19 is slice 6's).
fn with_pqc_extra(mut tx: Transaction) -> Transaction {
    let n = tx.prefix.outputs.len();
    tx.prefix.extra = if n == 0 {
        Vec::new()
    } else {
        tx_extra::serialize(&[
            TxExtraField::PqcKemCiphertext(vec![0x5A; HYBRID_KEM_CT_BYTES * n]),
            TxExtraField::PqcLeafEntries(conforming_pqc_leaf_blob(n)),
        ])
        .expect("two capped fields serialize")
    };
    tx
}

/// A two-output spend both copies accept: keys `G` and `4·G`, masks `2·G`
/// and `3·G` against one pseudo-out `5·G` (fee 0, so H18 balances), the
/// canonical BP+ layout for two outputs, one auth for its one input, and
/// I19's `extra`. Two outputs because the twin holds I1 (`>= 2`) at every
/// height and the crate does not yet.
fn spend2() -> Transaction {
    let mut tx = listed(point(9));
    tx.prefix.outputs = vec![
        Output {
            amount: 0,
            key: G,
            view_tag: 2,
        },
        Output {
            amount: 0,
            key: point(4),
            view_tag: 3,
        },
    ];
    if let Ct::Fcmp {
        base,
        prunable: Some(p),
        ..
    } = &mut tx.ct
    {
        base.enc_amounts = vec![[0x11; 9]; 2];
        base.enc_labels = vec![[0x22; 9]; 2];
        base.commitments = vec![TWO_G, point(3)];
        p.bulletproofs = vec![bp_plus_layout_for(2)];
        p.pseudo_outs = vec![point(5)];
    }
    with_pqc_extra(tx)
}

/// A serve-credit both copies accept: the fixture with the prunable region
/// `RF-D1` gave it — one pruned pass record for its one vin, and no spend
/// material.
fn serve_credit_ok() -> Transaction {
    let mut tx = serve_credit_only([0x51; 32]);
    if let Ct::Fcmp { prunable, .. } = &mut tx.ct {
        *prunable = Some(shekyl_wire::Prunable {
            bulletproofs: Vec::new(),
            tree_depth: 0,
            fcmp_proof: Vec::new(),
            pseudo_outs: Vec::new(),
            serve_credit_pruned: vec![vec![0x01; 4]],
        });
    }
    tx
}

/// The fixture coinbase with I19's `extra`.
fn coinbase_ok(height: u64) -> Transaction {
    with_pqc_extra(coinbase(height))
}

/// A bond-post input with a canonical hybrid key and `kind`; the type's
/// minimum otherwise.
fn bond_post_input(hybrid_key_len: usize, kind: BondPostKind) -> Input {
    Input::BondPost(Box::new(BondPost {
        hybrid_public_key: vec![0xB1; hybrid_key_len],
        p_canonical_id: shekyl_types::PCanonicalId::from_bytes([0xB0; 32]),
        kind,
        holdings: Holdings::CompleteTree,
        bonded_total_atomic: 0,
        bond_credit: 0,
        bond_debit: 0,
    }))
}

fn serve_credit_input() -> Input {
    let mut canonical_bytes = vec![TAG_INPUT_SERVE_CREDIT];
    canonical_bytes.extend_from_slice(&[0x52; 32]);
    Input::ServeCredit { canonical_bytes }
}

fn emission_input() -> Input {
    Input::ArchivalRewardEmission {
        canonical_bytes: vec![
            shekyl_wire::transaction::TAG_INPUT_ARCHIVAL_REWARD_EMISSION,
            0,
        ],
    }
}

fn spend_input(k: usize) -> Input {
    Input::ToKey {
        amount: 0,
        key_offsets: Vec::new(),
        key_image: point(k),
    }
}

/// `spend2()` with `input` appended and an auth for it.
fn spend2_plus(input: Input) -> Transaction {
    let mut tx = spend2();
    tx.prefix.inputs.push(input);
    if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
        pqc_auths.push(pqc_auth_filler());
    }
    tx
}

/// A bond post standing alone (no funding spend) with `outputs` outputs and
/// `prunable` as given — the shape the twin's fee-only arm is reached by.
fn bond_post_alone(outputs: usize, prunable: Option<shekyl_wire::Prunable>) -> Transaction {
    let mut tx = spend2();
    tx.prefix.inputs = vec![bond_post_input(
        PQC_HYBRID_SINGLE_KEY_LEN,
        BondPostKind::Other(2),
    )];
    tx.prefix.outputs.truncate(outputs);
    if let Ct::Fcmp {
        base,
        pqc_auths,
        prunable: p,
        ..
    } = &mut tx.ct
    {
        base.enc_amounts.truncate(outputs);
        base.enc_labels.truncate(outputs);
        base.commitments.truncate(outputs);
        *pqc_auths = vec![pqc_auth_filler()];
        *p = prunable;
    }
    with_pqc_extra(tx)
}

// ---- the trips ------------------------------------------------------------

fn j2_empty_pass_record() -> Transaction {
    let mut tx = serve_credit_ok();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut tx.ct
    {
        p.serve_credit_pruned = vec![Vec::new()];
    }
    tx
}

fn j11_short_hybrid_key() -> Transaction {
    spend2_plus(bond_post_input(5, BondPostKind::Other(2)))
}

fn j12_short_bond_spend_pk() -> Transaction {
    spend2_plus(bond_post_input(
        PQC_HYBRID_SINGLE_KEY_LEN,
        BondPostKind::JoinMarket {
            bond_spend_pk: vec![0xC0; 5],
            endpoint: [0xE0; shekyl_wire::transaction::BOND_POST_ENDPOINT_LEN],
        },
    ))
}

fn h4_no_inputs() -> Transaction {
    let mut tx = spend2();
    tx.prefix.inputs.clear();
    tx
}

fn h19_seventeen_outputs() -> Transaction {
    let mut tx = spend2();
    let out = tx.prefix.outputs[0].clone();
    tx.prefix.outputs = vec![out; 17];
    tx
}

fn h5_gen_beside_a_spend() -> Transaction {
    spend2_plus(Input::Gen(0))
}

fn h6_serve_credit_beside_a_spend() -> Transaction {
    spend2_plus(serve_credit_input())
}

fn h20_serve_credit_with_an_auth() -> Transaction {
    let mut tx = serve_credit_ok();
    if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
        pqc_auths.push(pqc_auth_filler());
    }
    tx
}

fn h6_two_bond_posts() -> Transaction {
    let one = bond_post_input(PQC_HYBRID_SINGLE_KEY_LEN, BondPostKind::Other(2));
    let mut tx = spend2_plus(one);
    tx.prefix.inputs.push(bond_post_input(
        PQC_HYBRID_SINGLE_KEY_LEN,
        BondPostKind::Other(3),
    ));
    tx
}

fn h6_two_emissions() -> Transaction {
    let mut tx = spend2_plus(emission_input());
    tx.prefix.inputs.push(emission_input());
    tx
}

fn h6_emission_beside_a_bond_post() -> Transaction {
    let mut tx = spend2_plus(emission_input());
    tx.prefix.inputs.push(bond_post_input(
        PQC_HYBRID_SINGLE_KEY_LEN,
        BondPostKind::Other(2),
    ));
    tx
}

fn m4_extra_over_the_relay_cap() -> Transaction {
    let mut tx = spend2();
    tx.prefix.extra = vec![0xEE; MAX_TX_EXTRA + 1];
    tx
}

fn h1_a_megabyte_proof() -> Transaction {
    let mut tx = spend2();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut tx.ct
    {
        p.fcmp_proof = vec![0xF0; MAX_TX_SIZE];
    }
    tx
}

fn h16_the_sentinel() -> Transaction {
    let mut tx = spend2();
    tx.prefix.unlock_time = UNLOCK_TIME_BLOCK_SENTINEL;
    tx
}

fn i4_nine_inputs() -> Transaction {
    let mut tx = spend2();
    tx.prefix.inputs = (1..=9).map(spend_input).collect();
    tx
}

fn i6_offsets() -> Transaction {
    let mut tx = spend2();
    if let Some(Input::ToKey { key_offsets, .. }) = tx.prefix.inputs.get_mut(0) {
        *key_offsets = vec![7, 0];
    }
    tx
}

fn i5_ascending_key_images() -> Transaction {
    let mut tx = spend2();
    let (mut a, mut b) = (point(9), point(10));
    if a > b {
        core::mem::swap(&mut a, &mut b);
    }
    tx.prefix.inputs = [a, b]
        .into_iter()
        .map(|key_image| Input::ToKey {
            amount: 0,
            key_offsets: Vec::new(),
            key_image,
        })
        .collect();
    tx
}

fn h15_null_ct_on_a_spend() -> Transaction {
    let mut tx = spend2();
    let Ct::Fcmp { base, .. } = &tx.ct else {
        unreachable!("spend2 is Fcmp")
    };
    tx.ct = Ct::Null(base.clone());
    tx
}

fn f4_no_outputs(cb: &mut Transaction) {
    cb.prefix.outputs.clear();
    cb.prefix.extra.clear();
    if let Ct::Null(base) = &mut cb.ct {
        base.enc_amounts.clear();
        base.enc_labels.clear();
        base.commitments.clear();
    }
}

fn f3_fcmp_ct(cb: &mut Transaction) {
    let Ct::Null(base) = &cb.ct else {
        unreachable!("the fixture coinbase is Null")
    };
    cb.ct = Ct::Fcmp {
        fee: 0,
        reference_block: shekyl_types::BlockHash::from_bytes([0x99; 32]),
        base: base.clone(),
        pqc_auths: Vec::new(),
        prunable: None,
    };
}

fn i16_oversized_key_blob() -> Transaction {
    let mut tx = spend2();
    if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
        pqc_auths[0].hybrid_public_key = vec![0xAB; PQC_MAX_PUBLIC_KEY_BLOB + 1];
    }
    tx
}

fn h8_short_base_arrays() -> Transaction {
    let mut tx = spend2();
    if let Ct::Fcmp { base, .. } = &mut tx.ct {
        base.enc_amounts.truncate(1);
    }
    tx
}

fn i1_one_output_spend() -> Transaction {
    with_pqc_extra(listed(point(9)))
}

fn i1_one_output_bond_post() -> Transaction {
    let prunable = shekyl_wire::Prunable {
        bulletproofs: vec![bp_plus_layout_for(1)],
        tree_depth: 0,
        fcmp_proof: vec![0xF0],
        pseudo_outs: Vec::new(),
        serve_credit_pruned: Vec::new(),
    };
    bond_post_alone(1, Some(prunable))
}

fn i8_no_auths() -> Transaction {
    let mut tx = spend2();
    if let Ct::Fcmp { pqc_auths, .. } = &mut tx.ct {
        pqc_auths.clear();
    }
    tx
}

fn h19_no_proof() -> Transaction {
    let mut tx = spend2();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut tx.ct
    {
        p.bulletproofs.clear();
    }
    tx
}

fn h19_layout_for_the_wrong_output_count() -> Transaction {
    let mut tx = spend2();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut tx.ct
    {
        p.bulletproofs = vec![bp_plus_layout_for(1)];
    }
    tx
}

fn i9_no_pseudo_outs() -> Transaction {
    let mut tx = spend2();
    if let Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut tx.ct
    {
        p.pseudo_outs.clear();
    }
    tx
}

fn pruned_form_bond_post_with_an_output() -> Transaction {
    bond_post_alone(1, None)
}

fn pruned_form_bond_post_with_an_auth() -> Transaction {
    bond_post_alone(0, None)
}

// ---- judging --------------------------------------------------------------

const LONE: Locus = Locus::Tx { slot: TxSlot::Lone };
const MINER: Locus = Locus::Tx {
    slot: TxSlot::Miner,
};

/// A one-block chain, so a candidate connects at height 1 — where F4's
/// genesis exemption does not apply.
fn one_block() -> MockChain {
    MockChain::default().push(recorded(1_000), root(1))
}

/// Both stages against `chain`; the mock never faults.
fn judge_on(chain: &MockChain, candidate: Candidate) -> Verdict<()> {
    let formed = match form(
        candidate,
        &RuleSet::GENESIS,
        &MockSubstrate::default(),
        expected_seed(chain),
        FormAttempt::FIRST,
    ) {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => return Err(refused),
        Err(Faulted) => unreachable!("the default MockSubstrate never faults"),
    };
    chain.with_view(|view| {
        judged(validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &Trust::UNANCHORED,
        ))
        .map(|_valid: ChainValid<_>| ())
    })
}

/// Whether a rendered message came from the source fragment: the fragment's
/// literal pieces (between its `{…}` placeholders) appear in `msg`, in
/// order. `"nbp {} != 1"` matches `"nbp 0 != 1"`.
fn rendered_from(fragment: &str, msg: &str) -> bool {
    let mut rest = msg;
    let mut literal = fragment;
    loop {
        let (piece, after) = match literal.find('{') {
            Some(open) => {
                let close = literal[open..]
                    .find('}')
                    .map_or(literal.len(), |c| open + c + 1);
                (&literal[..open], &literal[close..])
            }
            None => (literal, ""),
        };
        match rest.find(piece) {
            Some(at) => rest = &rest[at + piece.len()..],
            None => return false,
        }
        if after.is_empty() {
            return true;
        }
        literal = after;
    }
}

/// The twin refuses `tx` **on this arm**: its message renders the site's
/// fragment. An earlier arm firing is a failure — the trip did not reach
/// its subject.
fn twin_refuses_on(site: &Site, tx: &Transaction) {
    let err = tx
        .validate()
        .expect_err("the twin refuses the tripping transaction");
    let msg = err.to_string();
    assert!(
        rendered_from(site.fragment, &msg),
        "the twin refused {:?} on another arm: {msg}",
        site.fragment
    );
}

/// The tripping value does not survive the wire: serialize-then-parse either
/// fails or yields a different transaction. What "by construction" means
/// for an in-memory arm.
fn does_not_round_trip(tx: &Transaction) -> bool {
    !Transaction::from_bytes(&tx.serialize()).is_ok_and(|back| back == *tx)
}

/// Hold the crate to the row by the row's status (the self-arming form).
fn hold_to_registry(row: CenRow, verdict: Verdict<()>, tx: &Transaction, locus: Locus) {
    match row.status() {
        RowStatus::Implemented | RowStatus::EnforcedAt => {
            assert_refused(verdict, row, locus);
        }
        RowStatus::ByConstruction => assert!(
            does_not_round_trip(tx),
            "{row} is held by construction, but the value the twin refused round-trips the wire"
        ),
        RowStatus::Pending => {
            // Nothing to hold to yet. When the row flips, the arm above runs
            // and demands the refusal — no pin to update.
        }
        RowStatus::HeldByCxx => {
            panic!("{row} is held by the C++; a wire arm keyed to it is a classification error")
        }
    }
}

fn run(site: &Site) {
    match site.trip {
        Trip::None => {}
        Trip::Lone(build, expect) => {
            let tx = build();
            twin_refuses_on(site, &tx);
            let verdict = tx_form(&tx, TxSlot::Lone, &RuleSet::GENESIS).map(|_| ());
            match (site.arm, expect) {
                (Arm::Rule(row), Expect::FromRegistry) => {
                    hold_to_registry(row, verdict, &tx, LONE);
                }
                (_, Expect::Diverges { outcome, .. }) => match (outcome, verdict) {
                    (Outcome::Accepted, Ok(())) => {}
                    (Outcome::RefusedOn(row), Err(refused)) if refused.rule == row => {}
                    (outcome, verdict) => panic!(
                        "{:?}: recorded divergence is {outcome:?}, tx_form said {verdict:?}",
                        site.fragment
                    ),
                },
                (arm, expect) => panic!("{:?}: {arm:?} with {expect:?}", site.fragment),
            }
        }
        Trip::Coinbase(mutate, expect) => {
            let chain = one_block();
            let mut candidate = candidate_on(&chain, Vec::new());
            candidate.block.miner_transaction = coinbase_ok(1);
            mutate(&mut candidate.block.miner_transaction);
            twin_refuses_on(site, &candidate.block.miner_transaction);
            let (Arm::Rule(row), Expect::FromRegistry) = (site.arm, expect) else {
                panic!(
                    "{:?}: a coinbase trip is a registry-held rule",
                    site.fragment
                )
            };
            let cb = candidate.block.miner_transaction.clone();
            hold_to_registry(row, judge_on(&chain, candidate), &cb, MINER);
        }
    }
}

// ---- the tests --------------------------------------------------------------

/// The table is the file: one row per `Err(` site, each fragment found as
/// many times as it is listed, and the four counts pinned. A new arm in the
/// twin fails here until it has a row.
#[test]
fn every_refusal_arm_of_the_twin_is_classified() {
    let err_sites = TWIN_SOURCE.matches("Err(").count();
    assert_eq!(
        err_sites,
        SITES.len(),
        "shekyl-wire/src/transaction.rs has {err_sites} `Err(` sites and the table has {} rows: \
         classify the new arm (parse / rule → row / policy → row / invariant)",
        SITES.len()
    );
    for site in SITES {
        let listed = SITES.iter().filter(|s| s.fragment == site.fragment).count();
        let found = TWIN_SOURCE.matches(site.fragment).count();
        assert_eq!(
            found, listed,
            "fragment {:?} occurs {found} time(s) in the twin and {listed} time(s) in the table",
            site.fragment
        );
    }
    let count = |f: fn(&Arm) -> bool| SITES.iter().filter(|s| f(&s.arm)).count();
    let parse = count(|a| matches!(a, Arm::Parse));
    let rule = count(|a| matches!(a, Arm::Rule(_)));
    let policy = count(|a| matches!(a, Arm::Policy(_)));
    let invariant = count(|a| matches!(a, Arm::Invariant));
    assert_eq!(
        (parse, rule, policy, invariant),
        (15, 38, 1, 5),
        "the four counts (parse, rule, policy, invariant) moved — re-derive them, do not re-pin"
    );
    assert_eq!(parse + rule + policy + invariant, 59);
}

/// Shape: a trip is a rule or a policy arm's; a rule arm without one is a
/// parser arm whose row is either held by construction or has an in-memory
/// twin here keyed to the same row.
#[test]
fn every_rule_arm_is_held_somewhere() {
    for site in SITES {
        match (site.arm, site.trip) {
            (Arm::Parse | Arm::Invariant, Trip::None) | (Arm::Policy(_), Trip::Lone(..)) => {}
            (Arm::Parse | Arm::Invariant, _) => {
                panic!(
                    "{:?}: a parse/invariant arm has nothing to trip",
                    site.fragment
                )
            }
            (Arm::Policy(_), _) => panic!("{:?}: a policy arm carries its trip", site.fragment),
            (Arm::Rule(_), Trip::Lone(..) | Trip::Coinbase(..)) => assert_ne!(
                site.face,
                Face::Read,
                "{:?}: a read-face arm cannot be tripped by a value",
                site.fragment
            ),
            (Arm::Rule(row), Trip::None) => {
                assert_eq!(
                    site.face,
                    Face::Read,
                    "{:?}: an in-memory rule arm carries its trip",
                    site.fragment
                );
                let by_construction = row.status() == RowStatus::ByConstruction;
                let mirrored = SITES
                    .iter()
                    .any(|s| s.arm == Arm::Rule(row) && !matches!(s.trip, Trip::None));
                assert!(
                    by_construction || mirrored,
                    "{:?}: read-face arm for {row}, which is neither by construction nor mirrored by an in-memory arm here",
                    site.fragment
                );
            }
        }
    }
}

/// The positive witness: the baseline passes both copies.
#[test]
fn the_baseline_passes_the_twin_and_the_crate() {
    for (name, tx) in [("spend2", spend2()), ("serve_credit", serve_credit_ok())] {
        tx.validate()
            .unwrap_or_else(|e| panic!("the twin refuses the {name} baseline: {e}"));
        tx_form(&tx, TxSlot::Lone, &RuleSet::GENESIS)
            .unwrap_or_else(|r| panic!("the crate refuses the {name} baseline: {r}"));
    }
    let chain = one_block();
    let mut candidate = candidate_on(&chain, Vec::new());
    candidate.block.miner_transaction = coinbase_ok(1);
    candidate
        .block
        .miner_transaction
        .validate()
        .unwrap_or_else(|e| panic!("the twin refuses the coinbase baseline: {e}"));
    judge_on(&chain, candidate).unwrap_or_else(|r| panic!("the crate refuses the coinbase: {r}"));
}

/// Every trip reaches its arm in the twin, and the crate is held to the row
/// as the registry says — or the recorded divergence is exactly as recorded.
#[test]
fn every_trip_reaches_its_arm_and_the_crate_is_held_to_the_row() {
    for site in SITES {
        run(site);
    }
}

/// Every parse and invariant arm says why it is not a rule; every divergence
/// names its owner.
#[test]
fn every_non_rule_arm_carries_its_reason() {
    for site in SITES {
        match site.arm {
            Arm::Parse | Arm::Invariant | Arm::Policy(_) => assert!(
                !site.note.is_empty(),
                "{:?}: a non-rule arm says why it is not a rule",
                site.fragment
            ),
            Arm::Rule(_) => {
                if let Trip::Lone(_, Expect::Diverges { note, .. }) = site.trip {
                    assert!(!note.is_empty());
                }
            }
        }
    }
}
