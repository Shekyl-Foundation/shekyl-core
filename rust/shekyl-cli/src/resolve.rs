// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Parse-time command resolution.
//!
//! The parser turns raw user input into `ResolvedCommand` values with all
//! parameters baked in. After parsing, the command struct is immutable and
//! self-describing -- no handler reads session state during execution.
//!
//! The wallet2-era commands (accounts, key images, secret display, sweep) are
//! **removed**, not stubbed: they resolve to `Diagnostic` with a message that
//! names the replacement or the reason (rule 60; WI-RPC-2b deletions).

use shekyl_types::Timestamp;

/// A fully-resolved command ready for execution.
#[derive(Debug)]
pub enum ResolvedCommand {
    // -- Lifecycle --
    Create {
        filename: String,
    },
    Open {
        filename: String,
    },
    Close,
    Restore {
        filename: String,
        seed_words: Vec<String>,
    },
    Refresh,
    Status,
    Help,
    /// `help <command>` — the one-command usage block (CU-2).
    HelpCommand {
        topic: String,
    },
    Exit,

    // -- Balance / address --
    Balance,
    /// `address [--full | --out <path>]` (CU-4). The default is the short
    /// display form; `full` prints the whole ~2,030-character string;
    /// `out` writes it to a new 0600 file instead of the terminal.
    Address {
        full: bool,
        out: Option<String>,
    },

    // -- Transfers --
    Transfer {
        dest: String,
        amount: u64,
        /// RPC tier name (`ECONOMY` / `STANDARD` / `PRIORITY`). `None` is
        /// the server default.
        priority: Option<String>,
        /// Script-only confirmation skip. On a TTY it is not honored.
        yes: bool,
    },
    Transfers {
        incoming: bool,
        outgoing: bool,
        unmatched: bool,
    },
    ShowTransfer {
        txid: String,
    },
    GetTxNote {
        txid: String,
    },
    SetTxNote {
        txid: String,
        /// Taken verbatim from the input line (like `sign`): the note is
        /// user-authored text, and a token re-join would collapse the
        /// whitespace the user typed into it.
        note: String,
    },
    /// Give up on a dispatched send (`abandon_tx`, PR-SJ-3).
    Abandon {
        txid: String,
    },

    // -- Receiving (payment requests / URIs, WI-RPC-1) --
    RequestNew {
        amount: u64,
        label: String,
        /// Invoice expiry as wall-clock Unix seconds (`Timestamp`, RTN-6).
        /// Accepts an absolute unix timestamp or a relative duration
        /// (`1h`, `30m`, `7d`) resolved at parse time. The JSON-RPC wire
        /// still carries a raw integer.
        expiry: Option<Timestamp>,
    },
    RequestsList {
        filter: Option<String>,
    },
    HistoryIncomingUnattributed,
    MakeUri {
        address: Option<String>,
        amount: Option<u64>,
        label: Option<String>,
    },
    ParseUri {
        uri: String,
    },

    // -- Staking (WI-RPC-1) --
    /// Bare `stake`: posture, bond state, and the returnable amount.
    /// Not a write.
    Stake,
    /// Named shard set for a market join. Does not post until wallet-RPC
    /// accepts a shard set.
    StakeJoin {
        shard_ids: Vec<u64>,
    },
    StakedBalance,
    StakedOutputs,
    StakingInfo,

    // -- Archival principal staking actions (WI-RPC-5) --
    /// `stake_in <amount>` — fund the staking balance with an ordinary
    /// principal transfer. Amount only, by contract: cover is
    /// system-drawn and the `P` destination never appears on the wire.
    StakeIn {
        amount: u64,
        yes: bool,
    },
    /// `drain_balance` — the aggregate drainable staking amount, or an
    /// honest "syncing" (never a zero that would lie, rule 82 / F-D2).
    DrainBalance,
    /// `drain <amount>` — move staking funds back to this wallet. No fee,
    /// destination, or slot parameter exists, by contract (the
    /// anti-fingerprint pin): the fee is the canonical P-lane floor and
    /// the destination is this wallet's primary address, both engine-side.
    Drain {
        amount: u64,
        yes: bool,
    },
    /// `unstake` — post the permanent exit for the staked bond (PR-C).
    /// No arguments exist, by contract: the persona, fee, and amount are
    /// all engine-resolved, and the CLI's job is the irreversibility
    /// confirmation.
    Unstake {
        yes: bool,
    },
    /// `collect_unstaked` — sweep the released exit collateral back to
    /// this wallet, one pass at a time. No arguments, by contract.
    CollectUnstaked {
        yes: bool,
    },
    ShardListAll,
    ShardListMine,
    ShardShow {
        shard_id: u64,
    },
    ShardFetch {
        shard_id: u64,
    },

    // -- Fees (WI-RPC-1) --
    Fee {
        n_inputs: Option<i64>,
        n_outputs: Option<i64>,
    },

    ChainHealth,

    // -- Proofs (WI-RPC-3 surface) --
    GetTxProof {
        txid: String,
        address: String,
        message: Option<String>,
    },
    CheckTxProof {
        txid: String,
        address: String,
        proof: String,
        message: Option<String>,
    },
    GetReserveProof {
        amount: Option<u64>,
        message: Option<String>,
    },
    CheckReserveProof {
        address: String,
        proof: String,
        message: Option<String>,
    },

    // -- Message signing (PR-SM-2) --
    Sign {
        message: String,
    },
    Verify {
        address: String,
        signature: String,
        /// Required, not `Option`: the RPC contract treats an absent
        /// message as the empty string, and silently substituting `""`
        /// for a forgotten argument would turn an incomplete command
        /// into a confident false "INVALID" verdict (rule 82). Empty-
        /// message signatures remain verifiable over the RPC directly.
        message: String,
    },

    // -- Mining control (CU-3; the daemon does the hashing) --
    MineStart {
        /// `None` is the wallet-convenience default (`min(cores, 4)`),
        /// spelled `auto` on the command line.
        threads: Option<u64>,
    },
    MineStop,
    MineStatus,

    // -- Meta --
    Password,
    Rescan {
        hard: bool,
    },
    Version,
    /// `wallet` — the wallet summary (height, balance, address).
    Wallet,

    // -- Unknown --
    /// An unrecognized command token (the `other` catch-all). Rendered as
    /// "Unknown command: <cmd>. Type help ...".
    Unknown {
        cmd: String,
    },
    /// A parse-time diagnostic already formatted for the user: a usage error,
    /// removed-surface guidance, or a bad flag value. Kept distinct from
    /// `Unknown` so the dispatcher never has to guess which one it holds
    /// (previously disambiguated by a fragile whitespace heuristic).
    Diagnostic {
        message: String,
    },
}

/// The verbatim remainder of `input` after its first `n` whitespace-
/// delimited tokens, with the separating whitespace run stripped.
///
/// This is the message grammar for `sign` / `verify`: the message binds
/// into the signature byte-for-byte, so internal whitespace must survive
/// exactly as typed — [`trailing_message`]'s re-join would collapse it
/// and make a genuine signature unverifiable. The REPL trims the line
/// before parsing, so there is no trailing-whitespace ambiguity to
/// resolve here. `None` when fewer than `n` tokens exist or nothing
/// follows them.
pub(crate) fn raw_remainder(input: &str, n: usize) -> Option<&str> {
    let mut rest = input.trim_start();
    for _ in 0..n {
        let end = rest.find(char::is_whitespace)?;
        rest = rest[end..].trim_start();
    }
    (!rest.is_empty()).then_some(rest)
}

// ---------------------------------------------------------------------------
// Removed-surface rejection (rule 60 / rule 82: fail loud with guidance)
// ---------------------------------------------------------------------------

/// Reject removed wallet2-era flags instead of silently ignoring them.
pub(crate) fn reject_removed_flags(args: &[&str]) -> Option<String> {
    const REMOVED: &[(&str, &str)] = &[
        (
            "--subaddr-index",
            "subaddresses were deleted; the wallet has a single primary address",
        ),
        (
            "--subaddr-indices",
            "subaddresses were deleted; the wallet has a single primary address",
        ),
        (
            "--account",
            "accounts were deleted; use payment requests (\"request new\") to \
             attribute incoming payments",
        ),
        (
            "--do-not-relay",
            "not offered. It was step 1 of the Monero cold-signing workflow, \
             which Shekyl rejects permanently (an FCMP++ witness needs the \
             live chain). For fees use \"fee\"; transfer already shows the \
             built transaction and waits for confirmation — decline to \
             discard without broadcasting",
        ),
    ];
    for arg in args {
        for (flag, reason) in REMOVED {
            if arg == flag || arg.starts_with(&format!("{flag}=")) {
                return Some(format!("removed flag {flag}: {reason}"));
            }
        }
    }
    None
}

/// Reject removed wallet2-era commands with a message naming the replacement
/// or the reason (WI-RPC-2b deletions; `docs/CLI_PARITY_MATRIX.md`).
pub(crate) fn reject_removed_command(cmd: &str, args: &[&str]) -> Option<String> {
    let removed = match cmd {
        "account" => Some(
            "accounts were removed; the wallet has a single primary address. \
             Use \"address\" and payment requests (\"request new\") for \
             receive attribution.",
        ),
        "address" if args.first().copied() == Some("new") => Some(
            "\"address new\" was removed with the account model; the wallet \
             has a single primary address. Use \"request new\" to hand out \
             per-payer URIs.",
        ),
        "seed" | "viewkey" | "spendkey" => Some(
            "secret-displaying commands were removed: the wallet RPC \
             deliberately has no secret-egress surface. Your seed backup is \
             shown exactly once, at create/restore time.",
        ),
        "export_key_images" | "import_key_images" => Some(
            "key-image export/import was removed; Phase 2d sync bundles \
             replace the wallet2-era key-image workflow.",
        ),
        "get_tx_key" | "check_tx_key" => Some(
            "raw per-transaction-key export was rejected in the proofs \
             contract: the key is a bearer credential over the whole \
             transaction. Use \"prove payment\" / \"check payment\".",
        ),
        "sweep_all" => Some(
            "sweep_all was removed: no native sweep surface exists yet \
             (see docs/FOLLOWUPS.md for the reopening criterion).",
        ),
        "describe_transfer" | "sign_transfer" | "submit_transfer" => Some(
            "cold signing is not offered: an FCMP++ membership witness needs \
             the live curve tree, so an offline signer cannot deliver the \
             isolation the workflow claims. Rejected permanently \
             (V3_WALLET_DECISION_LOG.md 2026-09-07). Cold storage is your \
             seed phrase.",
        ),
        _ => None,
    };
    removed.map(|reason| format!("removed command {cmd}: {reason}"))
}

// ---------------------------------------------------------------------------
// Flag extraction helpers
// ---------------------------------------------------------------------------

/// Outcome of parsing an optional flag that carries a typed value.
///
/// Unlike an `Option<T>` return, this keeps "not given" and "given but
/// unparseable" distinct. The old `extract_flag_*` helpers collapsed both into
/// `None`, so a typo'd `--expiry tomorrow` / `--inputs five` was silently
/// dropped and the command ran with a wrong/default value (rule 82). Callers
/// must handle `Invalid` — the compiler no longer lets it be ignored.
pub(crate) enum FlagValue<T> {
    Absent,
    Set(T),
    Invalid(String),
}

/// Locate `flag` in `args` and return its raw value, accepting both spellings:
/// `--flag value` (two tokens) and `--flag=value` (one token). A bare trailing
/// `--flag` (or `--flag=`) yields `Some("")` — a present-but-empty value, not a
/// silent absence. `None` means the flag is not present at all.
pub(crate) fn flag_value<'a>(args: &[&'a str], flag: &str) -> Option<&'a str> {
    for (i, arg) in args.iter().enumerate() {
        if *arg == flag {
            return Some(args.get(i + 1).copied().unwrap_or(""));
        }
        if let Some(value) = arg
            .strip_prefix(flag)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some(value);
        }
    }
    None
}

/// Parse an optional flag value into a typed 3-state outcome. A present-but-
/// unparseable value (including a flag given with no value) surfaces as
/// `Invalid` — never a silent absence.
pub(crate) fn parse_flag<T: std::str::FromStr>(args: &[&str], flag: &str) -> FlagValue<T> {
    match flag_value(args, flag) {
        None => FlagValue::Absent,
        Some(raw) => match raw.parse::<T>() {
            Ok(v) => FlagValue::Set(v),
            Err(_) => FlagValue::Invalid(raw.to_owned()),
        },
    }
}

pub(crate) fn unix_now() -> Timestamp {
    Timestamp::from_raw(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

/// Absolute unix seconds, or a relative duration (`30s`/`5m`/`1h`/`7d`)
/// added to `now`. Invoice expiry is wall-clock, not block height (RTN-6).
pub(crate) fn parse_invoice_expiry(raw: &str, now: Timestamp) -> Option<Timestamp> {
    if let Ok(secs) = raw.parse::<u64>() {
        // A bare integer below INVOICE_UNIX_FLOOR is a height-shaped
        // leftover of the pre-RTN-6 CLI (`--expiry <height>`). Refuse
        // it rather than minting a 1970 timestamp.
        return Timestamp::from_invoice_unix(secs);
    }
    let duration = parse_duration_secs(raw)?;
    now.checked_add_secs(duration)
}

fn parse_duration_secs(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    let (last_idx, unit) = raw.char_indices().next_back()?;
    if last_idx == 0 {
        return None;
    }
    let digits = raw.get(..last_idx)?;
    let n: u64 = digits.parse().ok()?;
    let mul = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return None,
    };
    n.checked_mul(mul)
}

/// Construct a formatted parse-time [`ResolvedCommand::Diagnostic`].
pub(crate) fn diag(message: impl Into<String>) -> ResolvedCommand {
    ResolvedCommand::Diagnostic {
        message: message.into(),
    }
}

/// Like [`parse_flag`] but for string-valued flags: a present-but-empty value
/// (`--flag`, `--flag=`, or `--flag ""`) is `Invalid`, not an accepted empty
/// string — so it surfaces as a parse-time diagnostic instead of an empty value
/// crossing the wire (rule 82). `String`'s infallible `FromStr` makes the
/// generic `parse_flag` unable to reject empties, hence the dedicated form.
pub(crate) fn parse_flag_str(args: &[&str], flag: &str) -> FlagValue<String> {
    match flag_value(args, flag) {
        None => FlagValue::Absent,
        Some("") => FlagValue::Invalid(String::new()),
        Some(v) => FlagValue::Set(v.to_owned()),
    }
}

/// Remove `flag` and its value from `args`, handling both `--flag value` (two
/// tokens) and `--flag=value` (one token) so a stripped flag never leaks its
/// value into the positional args.
pub(crate) fn strip_flag_with_value<'a>(args: &[&'a str], flag: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if *arg == flag {
            skip_next = true;
            continue;
        }
        if arg
            .strip_prefix(flag)
            .is_some_and(|rest| rest.starts_with('='))
        {
            continue;
        }
        out.push(*arg);
    }
    out
}
