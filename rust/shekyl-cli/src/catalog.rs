// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The CLI command language: help, completion, and retired spellings.
//!
//! One table. Parsing lives in [`crate::grammar`]; this module is what
//! `help`, Tab, and a bad line all read, so those three cannot drift.

/// Subjects and product verbs offered at the first Tab.
pub const FIRST_WORDS: &[&str] = &[
    "wallet", "balance", "address", "status", "fee", "chain", "version", "stake", "shard", "tx",
    "request", "uri", "mine", "send", "prove", "check", "sign", "verify", "help", "exit",
];

/// Verbs of a subject. Absent means the word is a bare noun or a product verb.
pub fn subject_verbs(subject: &str) -> Option<&'static [&'static str]> {
    Some(match subject {
        "wallet" => &[
            "create", "open", "close", "restore", "password", "refresh", "rescan",
        ],
        "stake" => &[
            "add",
            "available",
            "balance",
            "collect",
            "exit",
            "join",
            "outputs",
            "return",
        ],
        "shard" => &["list", "show", "fetch"],
        "tx" => &["list", "show", "note", "abandon"],
        "request" => &["new", "list"],
        "uri" => &["make", "read"],
        "mine" => &["start", "stop", "status"],
        "prove" | "check" => &["payment", "reserve"],
        _ => return None,
    })
}

/// Words that follow `shard list`.
pub const SHARD_LIST_WHICH: &[&str] = &["all", "mine"];

/// Flags of a verb path (`"send"`, `"stake add"`, `"address"`).
pub fn flags_of(path: &str) -> &'static [&'static str] {
    match path {
        "address" => &["--full", "--out"],
        "send" | "stake add" | "stake return" | "stake exit" | "stake collect" => {
            if path == "send" {
                &["--priority", "--yes"]
            } else {
                &["--yes"]
            }
        }
        "tx list" => &["--in", "--out", "--unmatched"],
        "request new" => &["--expiry"],
        "request list" => &["--matched", "--all"],
        "uri make" => &["--amount", "--label", "--address"],
        "fee" => &["--inputs", "--outputs"],
        _ => &[],
    }
}

pub const PRIORITY_WORDS: &[&str] = &["economy", "standard", "high"];

/// Grouped help. Order is the order `help` prints.
pub const HELP_TREE: &str = "\
Wallet:
  wallet create <name>
  wallet open <name>
  wallet close
  wallet restore <name> <seed...>
  wallet password
  wallet refresh
  wallet rescan
  wallet

Money:
  balance
  send <amount> <address> [--priority economy|standard|high] [--yes]
  fee [--inputs N] [--outputs N]

History:
  tx list [--in | --out] [--unmatched]
  tx show <id>
  tx note <txid>
  tx note <txid> <text...>
  tx abandon <txid>

Requests:
  request new <amount> <label> [--expiry <unix|1h|7d>]
  request list [--matched | --all]
  uri make [--amount X] [--label L] [--address ADDR]
  uri read <uri>

Staking:
  stake
  stake balance
  stake outputs
  stake available
  stake add <amount> [--yes]
  stake return <amount> [--yes]
  stake exit [--yes]
  stake collect [--yes]
  stake join <shard-id>...

Shards:
  shard list all
  shard list mine
  shard show <id>
  shard fetch <id>

Mining:
  mine start [threads|auto]
  mine stop
  mine status

Proofs:
  prove payment <txid> <address> [message...]
  prove reserve [amount] [message...]
  check payment <txid> <address> <proof> [message...]
  check reserve <address> <proof> [message...]
  sign <message...>
  verify <address> <signature> <message...>

Other:
  address [--full | --out <path>]
  status
  chain
  version
  help [command]
  exit
";

/// Identity sequence for `help <command>`. `None` when the topic is unknown.
pub fn help_for(topic: &str) -> Option<&'static str> {
    let topic = topic.trim();
    Some(match topic {
        "wallet" | "wallet create" => "wallet create <name>",
        "wallet open" => "wallet open <name>",
        "wallet close" => "wallet close",
        "wallet restore" => "wallet restore <name> <seed...>",
        "wallet password" | "password" => "wallet password",
        "wallet refresh" | "refresh" => "wallet refresh",
        "wallet rescan" | "rescan" => "wallet rescan",
        "balance" => "balance",
        "address" => "address [--full | --out <path>]",
        "status" => "status",
        "fee" => "fee [--inputs N] [--outputs N]",
        "chain" => "chain",
        "version" => "version",
        "send" | "transfer" => "send <amount> <address> [--priority economy|standard|high] [--yes]",
        "tx" | "tx list" | "transfers" => "tx list [--in | --out] [--unmatched]",
        "tx show" | "show_transfer" => "tx show <id>",
        "tx note" | "get_tx_note" | "set_tx_note" => "tx note <txid> [<text...>]",
        "tx abandon" | "abandon" => "tx abandon <txid>",
        "request" | "request new" => "request new <amount> <label> [--expiry <unix|1h|7d>]",
        "request list" | "requests" => "request list [--matched | --all]",
        "uri" | "uri make" | "make_uri" => "uri make [--amount X] [--label L] [--address ADDR]",
        "uri read" | "parse_uri" => "uri read <uri>",
        "stake" => "stake",
        "stake balance" | "staked_balance" => "stake balance",
        "stake outputs" | "staked_outputs" => "stake outputs",
        "stake available" | "drain_balance" => "stake available",
        "stake add" | "stake_in" => "stake add <amount> [--yes]",
        "stake return" | "drain" => "stake return <amount> [--yes]",
        "stake exit" | "unstake" => "stake exit [--yes]",
        "stake collect" | "collect_unstaked" => "stake collect [--yes]",
        "stake join" => "stake join <shard-id>...",
        "shard" | "shard list" => "shard list all | shard list mine",
        "shard show" => "shard show <id>",
        "shard fetch" => "shard fetch <id>",
        "mine" | "mine start" | "start_mining" => "mine start [threads|auto]",
        "mine stop" | "stop_mining" => "mine stop",
        "mine status" | "mining_status" => "mine status",
        "prove" | "prove payment" | "get_tx_proof" => "prove payment <txid> <address> [message...]",
        "prove reserve" | "get_reserve_proof" => "prove reserve [amount] [message...]",
        "check" | "check payment" | "check_tx_proof" => {
            "check payment <txid> <address> <proof> [message...]"
        }
        "check reserve" | "check_reserve_proof" => "check reserve <address> <proof> [message...]",
        "sign" => "sign <message...>",
        "verify" => "verify <address> <signature> <message...>",
        "help" => "help [command]",
        "exit" | "quit" => "exit",
        _ => return None,
    })
}

/// A retired spelling. The value is the whole diagnostic line.
pub fn retired(tokens: &[&str]) -> Option<String> {
    let first = tokens.first().copied().unwrap_or("");
    let second = tokens.get(1).copied();
    if first == "stake" && second == Some("foundation") {
        return Some(
            "stake foundation → not a prompt command. CompleteTree is a startup flag \
             (--complete-tree-foundation): unbounded disk, no reward."
                .to_owned(),
        );
    }
    if first == "stake" && second == Some("info") {
        return Some("stake info → stake".to_owned());
    }
    if tokens.contains(&"--complete-tree-foundation") {
        return Some(
            "--complete-tree-foundation → startup flag, not a command word. \
             Unbounded disk, no reward."
                .to_owned(),
        );
    }
    let line = match (first, second) {
        ("transfer", _) => "transfer → send <amount> <address>",
        ("transfers", _) => "transfers → tx list",
        ("show_transfer", _) => "show_transfer → tx show <id>",
        ("get_tx_note", _) => "get_tx_note → tx note <txid>",
        ("set_tx_note", _) => "set_tx_note → tx note <txid> <text...>",
        ("abandon", _) => "abandon → tx abandon <txid>",
        ("stake_in", _) => "stake_in → stake add <amount>",
        ("drain", _) => "drain → stake return <amount>",
        ("drain_balance", _) => "drain_balance → stake available",
        ("unstake", _) => "unstake → stake exit",
        ("collect_unstaked", _) => "collect_unstaked → stake collect",
        ("get_tx_proof", _) => "get_tx_proof → prove payment <txid> <address> [message...]",
        ("check_tx_proof", _) => {
            "check_tx_proof → check payment <txid> <address> <proof> [message...]"
        }
        ("get_reserve_proof", _) => "get_reserve_proof → prove reserve [amount] [message...]",
        ("check_reserve_proof", _) => {
            "check_reserve_proof → check reserve <address> <proof> [message...]"
        }
        ("start_mining", _) => "start_mining → mine start [threads|auto]",
        ("stop_mining", _) => "stop_mining → mine stop",
        ("mining_status", _) => "mining_status → mine status",
        ("chain_health", _) => "chain_health → chain",
        ("staking_info", _) => "staking_info → stake",
        ("staked_balance", _) => "staked_balance → stake balance",
        ("staked_outputs", _) => "staked_outputs → stake outputs",
        ("refresh", _) => "refresh → wallet refresh",
        ("rescan", _) => "rescan → wallet rescan",
        ("parse_uri", _) => "parse_uri → uri read <uri>",
        ("make_uri", _) => "make_uri → uri make [--amount X] [--label L] [--address ADDR]",
        ("create", _) => "create → wallet create <name>",
        ("open", _) => "open → wallet open <name>",
        ("close", _) => "close → wallet close",
        ("restore", _) => "restore → wallet restore <name> <seed...>",
        ("password", _) => "password → wallet password",
        ("save", _) => {
            return Some(
                "save is not a command. Wallet state is persisted automatically after every operation."
                    .to_owned(),
            );
        }
        ("engine_info", _) => "engine_info → wallet",
        ("requests", _) => "requests → request list",
        ("history", _) => "history → tx list --in --unmatched",
        _ => return None,
    };
    Some(line.to_owned())
}

/// Lines that must not be written to the history file.
#[must_use]
pub fn omit_from_history(line: &str) -> bool {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    matches!(tokens.as_slice(), ["wallet", "restore", ..])
        || matches!(tokens.as_slice(), ["check", "payment", ..])
        || matches!(tokens.as_slice(), ["check", "reserve", ..])
        || matches!(tokens.as_slice(), ["verify", ..])
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
    let pool: Vec<&str> = match done {
        [] => FIRST_WORDS.to_vec(),
        ["shard", "list"] => SHARD_LIST_WHICH.to_vec(),
        [subject] => subject_verbs(subject)
            .map(<[&str]>::to_vec)
            .unwrap_or_default(),
        _ => flag_pool(done),
    };
    pool.into_iter()
        .filter(|word| word.starts_with(partial) && *word != partial)
        .map(|s| (*s).to_owned())
        .collect()
}

fn flag_pool(done: &[&str]) -> Vec<&'static str> {
    if done.last().copied() == Some("--priority") {
        return PRIORITY_WORDS.to_vec();
    }
    let path = command_path(done);
    flags_of(&path).to_vec()
}

fn command_path(done: &[&str]) -> String {
    match done {
        ["send", ..] => "send".to_owned(),
        ["address", ..] => "address".to_owned(),
        ["fee", ..] => "fee".to_owned(),
        ["tx", "list", ..] => "tx list".to_owned(),
        ["request", "new", ..] => "request new".to_owned(),
        ["request", "list", ..] => "request list".to_owned(),
        ["uri", "make", ..] => "uri make".to_owned(),
        ["stake", verb, ..] => format!("stake {verb}"),
        _ => String::new(),
    }
}
