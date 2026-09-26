// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The command language, once.
//!
//! [`CommandId`] is the vocabulary. [`meta`] is the only description of
//! each word: usage, parent, flags, and whether the line is secret.
//! Help, Tab, and retired spellings walk that description. Parsing of
//! arguments lives in [`crate::grammar`] and matches the same ids, so a
//! new command that is missing from either side fails to compile or
//! fails the tree test.

use std::fmt::Write as _;

/// One node of the command language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandId {
    Wallet,
    WalletCreate,
    WalletOpen,
    WalletClose,
    WalletRestore,
    WalletPassword,
    WalletRefresh,
    WalletRescan,
    Balance,
    Send,
    Fee,
    Address,
    Status,
    Chain,
    Version,
    Tx,
    TxList,
    TxShow,
    TxNote,
    TxAbandon,
    Request,
    RequestNew,
    RequestList,
    Uri,
    UriMake,
    UriRead,
    Stake,
    StakeBalance,
    StakeOutputs,
    StakeAvailable,
    StakeAdd,
    StakeReturn,
    StakeExit,
    StakeCollect,
    StakeJoin,
    Shard,
    ShardList,
    ShardListAll,
    ShardListMine,
    ShardShow,
    ShardFetch,
    Mine,
    MineStart,
    MineStop,
    MineStatus,
    Prove,
    ProvePayment,
    ProveReserve,
    Check,
    CheckPayment,
    CheckReserve,
    Sign,
    Verify,
    Help,
    Exit,
}

/// Every id, in help order within its family. Constructing each variant
/// here is what makes an unlinked command a dead-code failure.
const IDS: &[CommandId] = &[
    CommandId::Wallet,
    CommandId::WalletCreate,
    CommandId::WalletOpen,
    CommandId::WalletClose,
    CommandId::WalletRestore,
    CommandId::WalletPassword,
    CommandId::WalletRefresh,
    CommandId::WalletRescan,
    CommandId::Balance,
    CommandId::Send,
    CommandId::Fee,
    CommandId::Tx,
    CommandId::TxList,
    CommandId::TxShow,
    CommandId::TxNote,
    CommandId::TxAbandon,
    CommandId::Request,
    CommandId::RequestNew,
    CommandId::RequestList,
    CommandId::Uri,
    CommandId::UriMake,
    CommandId::UriRead,
    CommandId::Stake,
    CommandId::StakeBalance,
    CommandId::StakeOutputs,
    CommandId::StakeAvailable,
    CommandId::StakeAdd,
    CommandId::StakeReturn,
    CommandId::StakeExit,
    CommandId::StakeCollect,
    CommandId::StakeJoin,
    CommandId::Shard,
    CommandId::ShardList,
    CommandId::ShardListAll,
    CommandId::ShardListMine,
    CommandId::ShardShow,
    CommandId::ShardFetch,
    CommandId::Mine,
    CommandId::MineStart,
    CommandId::MineStop,
    CommandId::MineStatus,
    CommandId::Prove,
    CommandId::ProvePayment,
    CommandId::ProveReserve,
    CommandId::Check,
    CommandId::CheckPayment,
    CommandId::CheckReserve,
    CommandId::Sign,
    CommandId::Verify,
    CommandId::Address,
    CommandId::Status,
    CommandId::Chain,
    CommandId::Version,
    CommandId::Help,
    CommandId::Exit,
];

/// How a flag takes its argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlagKind {
    /// Present or absent.
    Switch,
    /// The next token, or `--flag=value`.
    Value,
    /// A value drawn from a closed set. Tab offers the set.
    OneOf(&'static [&'static str]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Flag {
    pub name: &'static str,
    pub kind: FlagKind,
}

impl Flag {
    const fn switch(name: &'static str) -> Self {
        Self {
            name,
            kind: FlagKind::Switch,
        }
    }

    const fn value(name: &'static str) -> Self {
        Self {
            name,
            kind: FlagKind::Value,
        }
    }

    const fn one_of(name: &'static str, words: &'static [&'static str]) -> Self {
        Self {
            name,
            kind: FlagKind::OneOf(words),
        }
    }
}

const NO_FLAGS: &[Flag] = &[];
const YES: &[Flag] = &[Flag::switch("--yes")];
const SEND_FLAGS: &[Flag] = &[
    Flag::one_of("--priority", &["economy", "standard", "high"]),
    Flag::switch("--yes"),
];
const ADDRESS_FLAGS: &[Flag] = &[Flag::switch("--full"), Flag::value("--out")];
const FEE_FLAGS: &[Flag] = &[Flag::value("--inputs"), Flag::value("--outputs")];
const TX_LIST_FLAGS: &[Flag] = &[
    Flag::switch("--in"),
    Flag::switch("--out"),
    Flag::switch("--unmatched"),
];
const REQUEST_NEW_FLAGS: &[Flag] = &[Flag::value("--expiry")];
const REQUEST_LIST_FLAGS: &[Flag] = &[Flag::switch("--matched"), Flag::switch("--all")];
const URI_MAKE_FLAGS: &[Flag] = &[
    Flag::value("--amount"),
    Flag::value("--label"),
    Flag::value("--address"),
];

struct Meta {
    word: &'static str,
    /// Extra words that invoke this same node (`quit` for `exit`).
    synonyms: &'static [&'static str],
    usage: &'static str,
    parent: Option<CommandId>,
    /// The node runs when no further word is present (`wallet`, `stake`).
    bare: bool,
    /// The line carries a seed, a proof, or a signature.
    omit_history: bool,
    flags: &'static [Flag],
}

#[allow(clippy::enum_glob_use)]
fn meta(id: CommandId) -> Meta {
    use CommandId::*;
    match id {
        Wallet => Meta {
            word: "wallet",
            synonyms: &[],
            usage: "wallet",
            parent: None,
            bare: true,
            omit_history: false,
            flags: NO_FLAGS,
        },
        WalletCreate => child("create", "wallet create <name>", Wallet),
        WalletOpen => child("open", "wallet open <name>", Wallet),
        WalletClose => child("close", "wallet close", Wallet),
        WalletRestore => Meta {
            word: "restore",
            synonyms: &[],
            usage: "wallet restore <name> <seed...>",
            parent: Some(Wallet),
            bare: false,
            omit_history: true,
            flags: NO_FLAGS,
        },
        WalletPassword => child("password", "wallet password", Wallet),
        WalletRefresh => child("refresh", "wallet refresh", Wallet),
        WalletRescan => child("rescan", "wallet rescan [hard]", Wallet),
        Balance => root("balance", "balance"),
        Send => Meta {
            word: "send",
            synonyms: &[],
            usage: "send <amount> <address> [--priority economy|standard|high] [--yes]",
            parent: None,
            bare: false,
            omit_history: false,
            flags: SEND_FLAGS,
        },
        Fee => Meta {
            word: "fee",
            synonyms: &[],
            usage: "fee [--inputs N] [--outputs N]",
            parent: None,
            bare: false,
            omit_history: false,
            flags: FEE_FLAGS,
        },
        Address => Meta {
            word: "address",
            synonyms: &[],
            usage: "address [--full | --out <path>]",
            parent: None,
            bare: false,
            omit_history: false,
            flags: ADDRESS_FLAGS,
        },
        Status => root("status", "status"),
        Chain => root("chain", "chain"),
        Version => root("version", "version"),
        Tx => interior("tx", "tx", None),
        TxList => Meta {
            word: "list",
            synonyms: &[],
            usage: "tx list [--in | --out] [--unmatched]",
            parent: Some(Tx),
            bare: false,
            omit_history: false,
            flags: TX_LIST_FLAGS,
        },
        TxShow => child("show", "tx show <id>", Tx),
        TxNote => child("note", "tx note <txid> [<text...>]", Tx),
        TxAbandon => child("abandon", "tx abandon <txid>", Tx),
        Request => interior("request", "request", None),
        RequestNew => Meta {
            word: "new",
            synonyms: &[],
            usage: "request new <amount> <label> [--expiry <unix|1h|7d>]",
            parent: Some(Request),
            bare: false,
            omit_history: false,
            flags: REQUEST_NEW_FLAGS,
        },
        RequestList => Meta {
            word: "list",
            synonyms: &[],
            usage: "request list [--matched | --all]",
            parent: Some(Request),
            bare: false,
            omit_history: false,
            flags: REQUEST_LIST_FLAGS,
        },
        Uri => interior("uri", "uri", None),
        UriMake => Meta {
            word: "make",
            synonyms: &[],
            usage: "uri make [--amount X] [--label L] [--address ADDR]",
            parent: Some(Uri),
            bare: false,
            omit_history: false,
            flags: URI_MAKE_FLAGS,
        },
        UriRead => child("read", "uri read <uri>", Uri),
        Stake => Meta {
            word: "stake",
            synonyms: &[],
            usage: "stake",
            parent: None,
            bare: true,
            omit_history: false,
            flags: NO_FLAGS,
        },
        StakeBalance => child("balance", "stake balance", Stake),
        StakeOutputs => child("outputs", "stake outputs", Stake),
        StakeAvailable => child("available", "stake available", Stake),
        StakeAdd => flagged("add", "stake add <amount> [--yes]", Stake, YES),
        StakeReturn => flagged("return", "stake return <amount> [--yes]", Stake, YES),
        StakeExit => flagged("exit", "stake exit [--yes]", Stake, YES),
        StakeCollect => flagged("collect", "stake collect [--yes]", Stake, YES),
        StakeJoin => child("join", "stake join <shard-id>...", Stake),
        Shard => interior("shard", "shard", None),
        ShardList => interior("list", "shard list", Some(Shard)),
        ShardListAll => child("all", "shard list all", ShardList),
        ShardListMine => child("mine", "shard list mine", ShardList),
        ShardShow => child("show", "shard show <id>", Shard),
        ShardFetch => child("fetch", "shard fetch <id>", Shard),
        Mine => interior("mine", "mine", None),
        MineStart => child("start", "mine start [threads|auto]", Mine),
        MineStop => child("stop", "mine stop", Mine),
        MineStatus => child("status", "mine status", Mine),
        Prove => interior("prove", "prove", None),
        ProvePayment => child(
            "payment",
            "prove payment <txid> <address> [message...]",
            Prove,
        ),
        ProveReserve => child("reserve", "prove reserve [amount] [message...]", Prove),
        Check => interior("check", "check", None),
        CheckPayment => Meta {
            word: "payment",
            synonyms: &[],
            usage: "check payment <txid> <address> <proof> [message...]",
            parent: Some(Check),
            bare: false,
            omit_history: true,
            flags: NO_FLAGS,
        },
        CheckReserve => Meta {
            word: "reserve",
            synonyms: &[],
            usage: "check reserve <address> <proof> [message...]",
            parent: Some(Check),
            bare: false,
            omit_history: true,
            flags: NO_FLAGS,
        },
        Sign => root("sign", "sign <message...>"),
        Verify => Meta {
            word: "verify",
            synonyms: &[],
            usage: "verify <address> <signature> <message...>",
            parent: None,
            bare: false,
            omit_history: true,
            flags: NO_FLAGS,
        },
        Help => root("help", "help [command]"),
        Exit => Meta {
            word: "exit",
            synonyms: &["quit"],
            usage: "exit",
            parent: None,
            bare: false,
            omit_history: false,
            flags: NO_FLAGS,
        },
    }
}

fn root(word: &'static str, usage: &'static str) -> Meta {
    Meta {
        word,
        synonyms: &[],
        usage,
        parent: None,
        bare: false,
        omit_history: false,
        flags: NO_FLAGS,
    }
}

fn child(word: &'static str, usage: &'static str, parent: CommandId) -> Meta {
    Meta {
        word,
        synonyms: &[],
        usage,
        parent: Some(parent),
        bare: false,
        omit_history: false,
        flags: NO_FLAGS,
    }
}

fn flagged(
    word: &'static str,
    usage: &'static str,
    parent: CommandId,
    flags: &'static [Flag],
) -> Meta {
    Meta {
        word,
        synonyms: &[],
        usage,
        parent: Some(parent),
        bare: false,
        omit_history: false,
        flags,
    }
}

/// A subject that only exists to hold verbs.
fn interior(word: &'static str, usage: &'static str, parent: Option<CommandId>) -> Meta {
    Meta {
        word,
        synonyms: &[],
        usage,
        parent,
        bare: false,
        omit_history: false,
        flags: NO_FLAGS,
    }
}

fn words_of(id: CommandId) -> Vec<&'static str> {
    let node = meta(id);
    let mut words = vec![node.word];
    words.extend_from_slice(node.synonyms);
    words
}

fn children_of(parent: CommandId) -> Vec<CommandId> {
    IDS.iter()
        .copied()
        .filter(|id| meta(*id).parent == Some(parent))
        .collect()
}

fn find_child(parent: Option<CommandId>, word: &str) -> Option<CommandId> {
    IDS.iter().copied().find(|id| {
        let node = meta(*id);
        node.parent == parent && words_of(*id).contains(&word)
    })
}

pub(crate) fn usage(id: CommandId) -> &'static str {
    meta(id).usage
}

pub(crate) fn flags_of(id: CommandId) -> &'static [Flag] {
    meta(id).flags
}

/// Where a token walk stopped.
pub(crate) enum Walk<'a> {
    /// `rest` is everything after the command path.
    Ready {
        id: CommandId,
        rest: &'a [&'a str],
    },
    /// The path names a subject that still needs a verb.
    NeedVerb {
        id: CommandId,
    },
    /// The next word is not a verb of `id`.
    UnknownVerb {
        id: CommandId,
        word: &'a str,
    },
    Unknown {
        word: String,
    },
}

pub(crate) fn walk<'a>(tokens: &'a [&'a str]) -> Walk<'a> {
    let Some(first) = tokens.first() else {
        return Walk::Unknown {
            word: String::new(),
        };
    };
    let Some(mut id) = find_child(None, first) else {
        return Walk::Unknown {
            word: (*first).to_string(),
        };
    };
    let mut index = 1;
    loop {
        if index >= tokens.len() {
            let node = meta(id);
            return if node.bare || children_of(id).is_empty() {
                Walk::Ready { id, rest: &[] }
            } else {
                Walk::NeedVerb { id }
            };
        }
        if let Some(child) = find_child(Some(id), tokens[index]) {
            id = child;
            index += 1;
            continue;
        }
        if children_of(id).is_empty() {
            return Walk::Ready {
                id,
                rest: &tokens[index..],
            };
        }
        return Walk::UnknownVerb {
            id,
            word: tokens[index],
        };
    }
}

pub(crate) fn need_verb(id: CommandId) -> String {
    let usages: Vec<&str> = children_of(id).into_iter().map(usage).collect();
    format!("{} → {}", usage(id), usages.join(" | "))
}

pub(crate) fn unknown_verb(id: CommandId, word: &str) -> String {
    format!("{}: no verb {word:?}.\n{}", meta(id).word, usage_block(id))
}

/// Positional tokens, switches, and values, split by the command's flags.
pub(crate) struct Split<'a> {
    pub positional: Vec<&'a str>,
    switches: Vec<&'static str>,
    values: Vec<(&'static str, &'a str)>,
}

impl Split<'_> {
    pub(crate) fn has(&self, name: &str) -> bool {
        self.switches.contains(&name)
    }

    pub(crate) fn value(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(flag, _)| *flag == name)
            .map(|(_, value)| *value)
    }
}

/// Reject unknown flags and flags whose value is missing or outside the set.
pub(crate) fn split_flags<'a>(
    args: &'a [&'a str],
    flags: &'static [Flag],
) -> Result<Split<'a>, String> {
    let mut positional = Vec::new();
    let mut switches = Vec::new();
    let mut values = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index];
        if let Some((name, raw)) = arg
            .split_once('=')
            .filter(|(name, _)| name.starts_with("--"))
        {
            let flag = known_flag(flags, name)?;
            if matches!(flag.kind, FlagKind::Switch) {
                return Err(format!("{} does not take a value", flag.name));
            }
            let value = nonempty(flag, raw)?;
            record(flag, Some(value), &mut switches, &mut values)?;
            index += 1;
            continue;
        }
        if arg.starts_with("--") {
            let flag = known_flag(flags, arg)?;
            match flag.kind {
                FlagKind::Switch => record(flag, None, &mut switches, &mut values)?,
                FlagKind::Value | FlagKind::OneOf(_) => {
                    let raw = args.get(index + 1).copied().unwrap_or("");
                    let value = nonempty(flag, raw)?;
                    record(flag, Some(value), &mut switches, &mut values)?;
                    index += 1;
                }
            }
            index += 1;
            continue;
        }
        positional.push(arg);
        index += 1;
    }
    Ok(Split {
        positional,
        switches,
        values,
    })
}

fn known_flag<'a>(flags: &'a [Flag], name: &str) -> Result<&'a Flag, String> {
    flags
        .iter()
        .find(|flag| flag.name == name)
        .ok_or_else(|| format!("unexpected flag {name}"))
}

fn nonempty<'a>(flag: &Flag, raw: &'a str) -> Result<&'a str, String> {
    if raw.is_empty() {
        Err(format!("{} expects a value", flag.name))
    } else if let FlagKind::OneOf(words) = flag.kind {
        if words.contains(&raw) {
            Ok(raw)
        } else {
            Err(format!(
                "{} expects {}, got {raw:?}",
                flag.name,
                words.join(", ")
            ))
        }
    } else {
        Ok(raw)
    }
}

fn record<'a>(
    flag: &Flag,
    value: Option<&'a str>,
    switches: &mut Vec<&'static str>,
    values: &mut Vec<(&'static str, &'a str)>,
) -> Result<(), String> {
    if switches.contains(&flag.name) || values.iter().any(|(name, _)| *name == flag.name) {
        return Err(format!("{} was given twice", flag.name));
    }
    match value {
        None => switches.push(flag.name),
        Some(value) => values.push((flag.name, value)),
    }
    Ok(())
}

/// A spelling that must not run.
enum Redirect {
    /// `{spelling} → {usage}`.
    To(CommandId),
    /// The refusal is not a rename.
    Say(&'static str),
}

struct Retired {
    tokens: &'static [&'static str],
    redirect: Redirect,
}

const RETIRED: &[Retired] = &[
    Retired {
        tokens: &["transfer"],
        redirect: Redirect::To(CommandId::Send),
    },
    Retired {
        tokens: &["transfers"],
        redirect: Redirect::To(CommandId::TxList),
    },
    Retired {
        tokens: &["show_transfer"],
        redirect: Redirect::To(CommandId::TxShow),
    },
    Retired {
        tokens: &["get_tx_note"],
        redirect: Redirect::To(CommandId::TxNote),
    },
    Retired {
        tokens: &["set_tx_note"],
        redirect: Redirect::To(CommandId::TxNote),
    },
    Retired {
        tokens: &["abandon"],
        redirect: Redirect::To(CommandId::TxAbandon),
    },
    Retired {
        tokens: &["stake_in"],
        redirect: Redirect::To(CommandId::StakeAdd),
    },
    Retired {
        tokens: &["drain"],
        redirect: Redirect::To(CommandId::StakeReturn),
    },
    Retired {
        tokens: &["drain_balance"],
        redirect: Redirect::To(CommandId::StakeAvailable),
    },
    Retired {
        tokens: &["unstake"],
        redirect: Redirect::To(CommandId::StakeExit),
    },
    Retired {
        tokens: &["collect_unstaked"],
        redirect: Redirect::To(CommandId::StakeCollect),
    },
    Retired {
        tokens: &["get_tx_proof"],
        redirect: Redirect::To(CommandId::ProvePayment),
    },
    Retired {
        tokens: &["check_tx_proof"],
        redirect: Redirect::To(CommandId::CheckPayment),
    },
    Retired {
        tokens: &["get_reserve_proof"],
        redirect: Redirect::To(CommandId::ProveReserve),
    },
    Retired {
        tokens: &["check_reserve_proof"],
        redirect: Redirect::To(CommandId::CheckReserve),
    },
    Retired {
        tokens: &["start_mining"],
        redirect: Redirect::To(CommandId::MineStart),
    },
    Retired {
        tokens: &["stop_mining"],
        redirect: Redirect::To(CommandId::MineStop),
    },
    Retired {
        tokens: &["mining_status"],
        redirect: Redirect::To(CommandId::MineStatus),
    },
    Retired {
        tokens: &["chain_health"],
        redirect: Redirect::To(CommandId::Chain),
    },
    Retired {
        tokens: &["staking_info"],
        redirect: Redirect::To(CommandId::Stake),
    },
    Retired {
        tokens: &["staked_balance"],
        redirect: Redirect::To(CommandId::StakeBalance),
    },
    Retired {
        tokens: &["staked_outputs"],
        redirect: Redirect::To(CommandId::StakeOutputs),
    },
    Retired {
        tokens: &["refresh"],
        redirect: Redirect::To(CommandId::WalletRefresh),
    },
    Retired {
        tokens: &["rescan"],
        redirect: Redirect::To(CommandId::WalletRescan),
    },
    Retired {
        tokens: &["parse_uri"],
        redirect: Redirect::To(CommandId::UriRead),
    },
    Retired {
        tokens: &["make_uri"],
        redirect: Redirect::To(CommandId::UriMake),
    },
    Retired {
        tokens: &["create"],
        redirect: Redirect::To(CommandId::WalletCreate),
    },
    Retired {
        tokens: &["open"],
        redirect: Redirect::To(CommandId::WalletOpen),
    },
    Retired {
        tokens: &["close"],
        redirect: Redirect::To(CommandId::WalletClose),
    },
    Retired {
        tokens: &["restore"],
        redirect: Redirect::To(CommandId::WalletRestore),
    },
    Retired {
        tokens: &["password"],
        redirect: Redirect::To(CommandId::WalletPassword),
    },
    Retired {
        tokens: &["engine_info"],
        redirect: Redirect::To(CommandId::Wallet),
    },
    Retired {
        tokens: &["requests"],
        redirect: Redirect::To(CommandId::RequestList),
    },
    Retired {
        tokens: &["history"],
        redirect: Redirect::Say("history → tx list --in --unmatched"),
    },
    Retired {
        tokens: &["save"],
        redirect: Redirect::Say(
            "save is not a command. Wallet state is persisted automatically after every operation.",
        ),
    },
    Retired {
        tokens: &["stake", "info"],
        redirect: Redirect::To(CommandId::Stake),
    },
    Retired {
        tokens: &["stake", "foundation"],
        redirect: Redirect::Say(
            "stake foundation → not a prompt command. CompleteTree is a startup flag \
             (--complete-tree-foundation): unbounded disk, no reward.",
        ),
    },
];

const COMPLETE_TREE_FLAG: &str =
    "--complete-tree-foundation → startup flag, not a command word. Unbounded disk, no reward.";

fn longest_retired(tokens: &[&str]) -> Option<&'static Retired> {
    RETIRED
        .iter()
        .filter(|retired| tokens.starts_with(retired.tokens))
        .max_by_key(|retired| retired.tokens.len())
}

fn retired_text(retired: &Retired) -> String {
    match retired.redirect {
        Redirect::Say(message) => message.to_owned(),
        Redirect::To(id) => format!("{} → {}", retired.tokens.join(" "), usage(id)),
    }
}

fn retired_omits_history(retired: &Retired) -> bool {
    match retired.redirect {
        Redirect::To(id) => meta(id).omit_history,
        Redirect::Say(_) => false,
    }
}

/// Diagnostic for a retired line, if `tokens` begins with one.
pub fn retired_message(tokens: &[&str]) -> Option<String> {
    if tokens.iter().any(|token| {
        *token == "--complete-tree-foundation" || token.starts_with("--complete-tree-foundation=")
    }) {
        return Some(COMPLETE_TREE_FLAG.to_owned());
    }
    longest_retired(tokens).map(retired_text)
}

/// Lines that must not be written to the history file.
///
/// Retired secret-bearing spellings are included: `restore <seed>` and
/// `check_tx_proof` are refused, and the refusal must not archive the line.
#[must_use]
pub fn omit_from_history(line: &str) -> bool {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if let Some(retired) = longest_retired(&tokens) {
        return retired_omits_history(retired);
    }
    match walk(&tokens) {
        Walk::Ready { id, .. } => meta(id).omit_history,
        _ => false,
    }
}

const HELP_GROUPS: &[(&str, &[CommandId])] = &[
    (
        "Wallet",
        &[
            CommandId::WalletCreate,
            CommandId::WalletOpen,
            CommandId::WalletClose,
            CommandId::WalletRestore,
            CommandId::WalletPassword,
            CommandId::WalletRefresh,
            CommandId::WalletRescan,
            CommandId::Wallet,
        ],
    ),
    (
        "Money",
        &[CommandId::Balance, CommandId::Send, CommandId::Fee],
    ),
    (
        "History",
        &[
            CommandId::TxList,
            CommandId::TxShow,
            CommandId::TxNote,
            CommandId::TxAbandon,
        ],
    ),
    (
        "Requests",
        &[
            CommandId::RequestNew,
            CommandId::RequestList,
            CommandId::UriMake,
            CommandId::UriRead,
        ],
    ),
    (
        "Staking",
        &[
            CommandId::Stake,
            CommandId::StakeBalance,
            CommandId::StakeOutputs,
            CommandId::StakeAvailable,
            CommandId::StakeAdd,
            CommandId::StakeReturn,
            CommandId::StakeExit,
            CommandId::StakeCollect,
            CommandId::StakeJoin,
        ],
    ),
    (
        "Shards",
        &[
            CommandId::ShardListAll,
            CommandId::ShardListMine,
            CommandId::ShardShow,
            CommandId::ShardFetch,
        ],
    ),
    (
        "Mining",
        &[
            CommandId::MineStart,
            CommandId::MineStop,
            CommandId::MineStatus,
        ],
    ),
    (
        "Proofs",
        &[
            CommandId::ProvePayment,
            CommandId::ProveReserve,
            CommandId::CheckPayment,
            CommandId::CheckReserve,
            CommandId::Sign,
            CommandId::Verify,
        ],
    ),
    (
        "Other",
        &[
            CommandId::Address,
            CommandId::Status,
            CommandId::Chain,
            CommandId::Version,
            CommandId::Help,
            CommandId::Exit,
        ],
    ),
];

/// Grouped help. Order is the order `help` prints.
pub fn help_listing() -> String {
    let mut out = String::new();
    for (index, (title, ids)) in HELP_GROUPS.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let _written = writeln!(out, "{title}:");
        for id in *ids {
            let _written = writeln!(out, "  {}", usage(*id));
        }
    }
    out
}

fn usage_block(id: CommandId) -> String {
    let mut lines = Vec::new();
    collect_usages(id, &mut lines);
    lines.join("\n")
}

fn collect_usages(id: CommandId, out: &mut Vec<&'static str>) {
    let node = meta(id);
    let children = children_of(id);
    if node.bare || children.is_empty() {
        out.push(node.usage);
    }
    for child in children {
        collect_usages(child, out);
    }
}

fn exact_command(tokens: &[&str]) -> Option<CommandId> {
    match walk(tokens) {
        Walk::Ready { id, rest: [] } | Walk::NeedVerb { id } => Some(id),
        _ => None,
    }
}

/// Usage for `help <topic>`. `None` when the topic is unknown.
pub fn help_for(topic: &str) -> Option<String> {
    let tokens: Vec<&str> = topic.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }
    if let Some(id) = exact_command(&tokens) {
        return Some(usage_block(id));
    }
    let retired = RETIRED
        .iter()
        .find(|retired| retired.tokens == tokens.as_slice())?;
    match retired.redirect {
        Redirect::To(id) => Some(usage_block(id)),
        Redirect::Say(_) => None,
    }
}

/// Tab candidates for the token being typed.
pub fn complete(line_before_cursor: &str) -> (usize, Vec<String>) {
    let trailing_space = line_before_cursor.ends_with(' ');
    let words: Vec<&str> = line_before_cursor.split_whitespace().collect();
    let (done, partial): (Vec<&str>, &str) = if trailing_space {
        (words, "")
    } else if let Some((last, rest)) = words.split_last() {
        (rest.to_vec(), *last)
    } else {
        (Vec::new(), "")
    };
    let start = if partial.is_empty() {
        line_before_cursor.len()
    } else {
        line_before_cursor.len() - partial.len()
    };
    let candidates = candidates(&done, partial);
    (start, candidates)
}

fn candidates(done: &[&str], partial: &str) -> Vec<String> {
    let pool = completion_pool(done);
    pool.into_iter()
        .filter(|word| word.starts_with(partial) && *word != partial)
        .map(str::to_owned)
        .collect()
}

fn completion_pool(done: &[&str]) -> Vec<&'static str> {
    if done.is_empty() {
        return IDS
            .iter()
            .copied()
            .filter(|id| meta(*id).parent.is_none())
            .flat_map(words_of)
            .collect();
    }
    let Some(mut id) = find_child(None, done[0]) else {
        return Vec::new();
    };
    let mut index = 1;
    while index < done.len() {
        if let Some(child) = find_child(Some(id), done[index]) {
            id = child;
            index += 1;
            continue;
        }
        break;
    }
    if index == done.len() && !children_of(id).is_empty() {
        return children_of(id).into_iter().flat_map(words_of).collect();
    }
    let args = &done[index..];
    if let Some(words) = value_words(id, args) {
        return words;
    }
    meta(id)
        .flags
        .iter()
        .map(|flag| flag.name)
        .filter(|name| !args.contains(name))
        .collect()
}

fn value_words(id: CommandId, args: &[&str]) -> Option<Vec<&'static str>> {
    let last = args.last().copied()?;
    let flag = meta(id).flags.iter().find(|flag| flag.name == last)?;
    match flag.kind {
        FlagKind::OneOf(words) => Some(words.to_vec()),
        FlagKind::Switch | FlagKind::Value => None,
    }
}

/// Whether `id` is a command an operator can be shown a usage line for.
#[cfg(test)]
fn listed(id: CommandId) -> bool {
    let node = meta(id);
    node.bare || children_of(id).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_command_is_in_help_once() {
        let listing = help_listing();
        for id in IDS {
            if !listed(*id) {
                continue;
            }
            let line = format!("  {}", usage(*id));
            assert!(listing.contains(&line), "{} missing from help", usage(*id));
        }
    }

    #[test]
    fn help_topic_follows_the_tree_and_the_retirement() {
        let send = help_for("send").unwrap();
        assert!(send.contains("send <amount> <address>"), "{send}");
        assert!(help_for("transfer").unwrap().contains("send"));
        assert!(help_for("stake").unwrap().contains("stake join"));
        assert!(help_for("no_such_command").is_none());
        assert!(help_for("save").is_none());
    }

    #[test]
    fn completion_offers_verbs_and_not_the_retired_foundation_word() {
        let stake = complete("stake ");
        assert!(stake.1.iter().any(|word| word == "join"));
        assert!(!stake.1.iter().any(|word| word == "foundation"));
        let priority = complete("send 1 addr --priority ");
        assert!(priority.1.iter().any(|word| word == "economy"));
    }

    #[test]
    fn retired_secret_lines_stay_out_of_history() {
        assert!(omit_from_history("restore name word word"));
        assert!(omit_from_history("wallet restore name word"));
        assert!(omit_from_history("check_tx_proof tx addr proof"));
        assert!(omit_from_history("check_reserve_proof addr proof"));
        assert!(omit_from_history("check payment tx addr proof"));
        assert!(omit_from_history("verify addr sig hello"));
        assert!(!omit_from_history("sign hello"));
        assert!(!omit_from_history("balance"));
    }
}
