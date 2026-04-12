// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! REPL command loop and dispatch for shekyl-cli.

use crate::wallet::WalletContext;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use zeroize::Zeroize;

const HELP_TEXT: &str = "\
Commands:
  create <filename>                   Create a new wallet
  open <filename>                     Open an existing wallet
  close                               Close the current wallet
  address                             Show the primary address
  balance                             Show balance (unlocked, locked)
  transfer <amount> <address>         Send SKL to an address
  transfers                           Show recent transactions
  seed                                Display the mnemonic seed
  restore <filename> <seed...>        Restore wallet from mnemonic seed
  refresh                             Sync with the daemon
  save                                Save wallet to disk
  status                              Show sync height and wallet state
  help                                Show this help
  exit                                Exit shekyl-cli";

pub fn repl(ctx: WalletContext) -> Result<(), Box<dyn std::error::Error>> {
    let mut rl = DefaultEditor::new()?;
    let hist = history_path().unwrap_or_default();

    if rl.load_history(&hist).is_err() {
        // No history file yet -- that's fine on first run.
    }

    println!("Welcome to shekyl-cli. Type \"help\" for commands.");

    loop {
        let prompt = if ctx.is_open() {
            "shekyl-cli [wallet open]> "
        } else {
            "shekyl-cli> "
        };

        match rl.readline(prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(line);

                let parts: Vec<&str> = line.splitn(3, char::is_whitespace).collect();
                let cmd = parts[0];
                let args = &parts[1..];

                match cmd {
                    "help" => println!("{HELP_TEXT}"),
                    "exit" | "quit" => {
                        if ctx.is_open() {
                            if let Err(e) = ctx.close() {
                                eprintln!("Warning: failed to close wallet: {e}");
                            }
                        }
                        break;
                    }
                    "create" => cmd_create(&ctx, args),
                    "open" => cmd_open(&ctx, args),
                    "close" => cmd_close(&ctx),
                    "address" => cmd_address(&ctx),
                    "balance" => cmd_balance(&ctx),
                    "transfer" => cmd_transfer(&ctx, args),
                    "transfers" => cmd_transfers(&ctx),
                    "seed" => cmd_seed(&ctx),
                    "restore" => cmd_restore(&ctx, args),
                    "refresh" => cmd_refresh(&ctx),
                    "save" => cmd_save(&ctx),
                    "status" => cmd_status(&ctx),
                    _ => eprintln!("Unknown command: {cmd}. Type \"help\" for available commands."),
                }
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                if ctx.is_open() {
                    if let Err(e) = ctx.close() {
                        eprintln!("Warning: failed to close wallet: {e}");
                    }
                }
                break;
            }
            Err(e) => {
                eprintln!("Input error: {e}");
                break;
            }
        }
    }

    let _ = rl.save_history(&hist);
    Ok(())
}

fn history_path() -> Option<String> {
    dirs::data_local_dir().map(|mut p| {
        p.push("shekyl-cli");
        let _ = std::fs::create_dir_all(&p);
        p.push("history.txt");
        p.to_string_lossy().into_owned()
    })
}

fn require_open(ctx: &WalletContext) -> bool {
    if !ctx.is_open() {
        eprintln!("No wallet is open. Use \"open <filename>\" or \"create <filename>\" first.");
        return false;
    }
    true
}

fn require_closed(ctx: &WalletContext) -> bool {
    if ctx.is_open() {
        eprintln!("A wallet is already open. Use \"close\" first.");
        return false;
    }
    true
}

fn read_password(prompt: &str) -> Option<String> {
    match crate::prompt_password(prompt) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("Failed to read password: {e}");
            None
        }
    }
}

fn cmd_create(ctx: &WalletContext, args: &[&str]) {
    if !require_closed(ctx) {
        return;
    }
    let filename = match args.first() {
        Some(f) => *f,
        None => {
            eprintln!("Usage: create <filename>");
            return;
        }
    };
    let Some(mut password) = read_password("New wallet password: ") else { return };
    let Some(confirm) = read_password("Confirm password: ") else {
        password.zeroize();
        return;
    };
    if password != confirm {
        eprintln!("Passwords do not match.");
        password.zeroize();
        return;
    }
    drop(confirm);

    match ctx.create(filename, &password, "English") {
        Ok(()) => println!("Wallet created: {filename}"),
        Err(e) => eprintln!("Failed to create wallet: {e}"),
    }
    password.zeroize();
}

fn cmd_open(ctx: &WalletContext, args: &[&str]) {
    if !require_closed(ctx) {
        return;
    }
    let filename = match args.first() {
        Some(f) => *f,
        None => {
            eprintln!("Usage: open <filename>");
            return;
        }
    };
    let Some(mut password) = read_password("Wallet password: ") else { return };

    match ctx.open(filename, &password) {
        Ok(()) => println!("Opened wallet: {filename}"),
        Err(e) => eprintln!("Failed to open wallet: {e}"),
    }
    password.zeroize();
}

fn cmd_close(ctx: &WalletContext) {
    if !require_open(ctx) {
        return;
    }
    match ctx.close() {
        Ok(()) => println!("Wallet closed."),
        Err(e) => eprintln!("Failed to close wallet: {e}"),
    }
}

fn cmd_address(ctx: &WalletContext) {
    if !require_open(ctx) {
        return;
    }
    match ctx.get_address(0) {
        Ok(val) => {
            if let Some(addr) = val.get("address").and_then(|a| a.as_str()) {
                println!("Primary address: {addr}");
            } else {
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Failed to get address: {e}"),
    }
}

fn cmd_balance(ctx: &WalletContext) {
    if !require_open(ctx) {
        return;
    }
    match ctx.get_balance(0) {
        Ok(val) => {
            let balance = val.get("balance").and_then(|v| v.as_u64()).unwrap_or(0);
            let unlocked = val.get("unlocked_balance").and_then(|v| v.as_u64()).unwrap_or(0);
            println!(
                "Balance:          {} SKL",
                format_amount(balance)
            );
            println!(
                "Unlocked balance: {} SKL",
                format_amount(unlocked)
            );
        }
        Err(e) => eprintln!("Failed to get balance: {e}"),
    }
}

fn cmd_transfer(ctx: &WalletContext, args: &[&str]) {
    if !require_open(ctx) {
        return;
    }
    if args.len() < 2 {
        eprintln!("Usage: transfer <amount> <address>");
        return;
    }

    let amount_str = args[0];
    let address = args[1];

    let atomic = match parse_amount(amount_str) {
        Some(a) => a,
        None => {
            eprintln!("Invalid amount: {amount_str}. Use decimal SKL (e.g. 1.5).");
            return;
        }
    };

    let destinations = serde_json::json!([{
        "amount": atomic,
        "address": address
    }]);

    println!("Sending {} SKL to {address}...", format_amount(atomic));

    match ctx.transfer(&destinations.to_string(), 0, 0) {
        Ok(val) => {
            if let Some(tx_hash) = val.get("tx_hash").and_then(|h| h.as_str()) {
                println!("Transaction sent: {tx_hash}");
            } else if let Some(tx_hash_list) = val.get("tx_hash_list").and_then(|l| l.as_array()) {
                for h in tx_hash_list {
                    if let Some(hash) = h.as_str() {
                        println!("Transaction sent: {hash}");
                    }
                }
            } else {
                println!("Transfer submitted.");
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Transfer failed: {e}"),
    }
}

fn cmd_transfers(ctx: &WalletContext) {
    if !require_open(ctx) {
        return;
    }
    match ctx.get_transfers(true, true, true, false, false, 0) {
        Ok(val) => {
            let mut found = false;
            for direction in &["in", "out", "pending"] {
                if let Some(txs) = val.get(direction).and_then(|v| v.as_array()) {
                    for tx in txs {
                        found = true;
                        let amount = tx.get("amount").and_then(|a| a.as_u64()).unwrap_or(0);
                        let height = tx.get("height").and_then(|h| h.as_u64()).unwrap_or(0);
                        let txid = tx.get("txid").and_then(|t| t.as_str()).unwrap_or("?");
                        println!(
                            "  [{direction:>7}] height={height:<8} amount={:<14} tx={txid}",
                            format_amount(amount)
                        );
                    }
                }
            }
            if !found {
                println!("No transactions found.");
            }
        }
        Err(e) => eprintln!("Failed to get transfers: {e}"),
    }
}

fn cmd_seed(ctx: &WalletContext) {
    if !require_open(ctx) {
        return;
    }

    eprintln!(
        "WARNING: Your mnemonic seed grants full access to your funds.\n\
         Never share it. Never enter it on a website."
    );
    eprint!("Type \"yes\" to display: ");
    let mut confirm = String::new();
    if std::io::stdin().read_line(&mut confirm).is_err() {
        eprintln!("Failed to read confirmation.");
        return;
    }
    if confirm.trim() != "yes" {
        println!("Cancelled.");
        return;
    }

    match ctx.query_key("mnemonic") {
        Ok(val) => {
            if let Some(key) = val.get("key").and_then(|k| k.as_str()) {
                println!("\n{key}\n");
            } else {
                println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
            }
        }
        Err(e) => eprintln!("Failed to retrieve seed: {e}"),
    }
}

fn cmd_restore(ctx: &WalletContext, args: &[&str]) {
    if !require_closed(ctx) {
        return;
    }
    if args.len() < 2 {
        eprintln!("Usage: restore <filename> <seed words...>");
        return;
    }
    let filename = args[0];
    let seed = args[1..].join(" ");

    let Some(mut password) = read_password("New wallet password: ") else { return };

    eprint!("Restore height (0 for full scan): ");
    let mut height_str = String::new();
    if std::io::stdin().read_line(&mut height_str).is_err() {
        eprintln!("Failed to read restore height.");
        password.zeroize();
        return;
    }
    let restore_height: u64 = height_str.trim().parse().unwrap_or(0);

    match ctx.restore_from_seed(filename, &seed, &password, "English", restore_height, "") {
        Ok(val) => {
            if let Some(addr) = val.get("address").and_then(|a| a.as_str()) {
                println!("Wallet restored: {filename}");
                println!("Address: {addr}");
            } else {
                println!("Wallet restored: {filename}");
            }
        }
        Err(e) => eprintln!("Failed to restore wallet: {e}"),
    }
    password.zeroize();
}

fn cmd_refresh(ctx: &WalletContext) {
    if !require_open(ctx) {
        return;
    }
    println!("Refreshing...");
    match ctx.refresh() {
        Ok(()) => println!("Refresh complete. Height: {}", ctx.get_height()),
        Err(e) => eprintln!("Refresh failed: {e}"),
    }
}

fn cmd_save(ctx: &WalletContext) {
    if !require_open(ctx) {
        return;
    }
    match ctx.store() {
        Ok(()) => println!("Wallet saved."),
        Err(e) => eprintln!("Failed to save wallet: {e}"),
    }
}

fn cmd_status(ctx: &WalletContext) {
    if ctx.is_open() {
        println!("Wallet: open");
        println!("Height: {}", ctx.get_height());
    } else {
        println!("Wallet: not open");
    }
}

fn format_amount(atomic: u64) -> String {
    let whole = atomic / 1_000_000_000_000;
    let frac = atomic % 1_000_000_000_000;
    if frac == 0 {
        format!("{whole}.000000000000")
    } else {
        format!("{whole}.{frac:012}")
    }
}

fn parse_amount(s: &str) -> Option<u64> {
    if let Some(dot_pos) = s.find('.') {
        let whole: u64 = s[..dot_pos].parse().ok()?;
        let frac_str = &s[dot_pos + 1..];
        if frac_str.len() > 12 {
            return None;
        }
        let padded = format!("{frac_str:0<12}");
        let frac: u64 = padded.parse().ok()?;
        whole.checked_mul(1_000_000_000_000)?.checked_add(frac)
    } else {
        let whole: u64 = s.parse().ok()?;
        whole.checked_mul(1_000_000_000_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_amount() {
        assert_eq!(format_amount(0), "0.000000000000");
        assert_eq!(format_amount(1_000_000_000_000), "1.000000000000");
        assert_eq!(format_amount(1_500_000_000_000), "1.500000000000");
        assert_eq!(format_amount(123_456_789), "0.000123456789");
    }

    #[test]
    fn test_parse_amount() {
        assert_eq!(parse_amount("1"), Some(1_000_000_000_000));
        assert_eq!(parse_amount("1.5"), Some(1_500_000_000_000));
        assert_eq!(parse_amount("0.000000000001"), Some(1));
        assert_eq!(parse_amount("1.0"), Some(1_000_000_000_000));
        assert_eq!(parse_amount("abc"), None);
        assert_eq!(parse_amount("1.0000000000001"), None); // >12 decimal places
    }

    #[test]
    fn test_parse_format_roundtrip() {
        for val in [0, 1, 999_999_999_999, 1_000_000_000_000, 123_456_789_012_345] {
            let formatted = format_amount(val);
            let parsed = parse_amount(&formatted).expect("roundtrip should succeed");
            assert_eq!(val, parsed, "roundtrip failed for {val}");
        }
    }
}
