// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Engine lifecycle commands: create, open, close, restore.

use crate::engine::EngineContext;
use zeroize::Zeroize;

pub fn cmd_create(ctx: &EngineContext, args: &[&str]) {
    if !super::require_closed(ctx) {
        return;
    }
    let filename = match args.first() {
        Some(f) => *f,
        None => {
            eprintln!("Usage: create <filename>");
            return;
        }
    };
    let Some(mut password) = super::read_password("New engine password: ") else {
        return;
    };
    let Some(confirm) = super::read_password("Confirm password: ") else {
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
        Ok(()) => println!("Engine created: {filename}"),
        Err(e) => eprintln!("Failed to create engine: {e}"),
    }
    password.zeroize();
}

pub fn cmd_open(ctx: &EngineContext, args: &[&str]) {
    if !super::require_closed(ctx) {
        return;
    }
    let filename = match args.first() {
        Some(f) => *f,
        None => {
            eprintln!("Usage: open <filename>");
            return;
        }
    };
    let Some(mut password) = super::read_password("Engine password: ") else {
        return;
    };

    match ctx.open(filename, &password) {
        Ok(()) => println!("Opened engine: {filename}"),
        Err(e) => eprintln!("Failed to open engine: {e}"),
    }
    password.zeroize();
}

pub fn cmd_close(ctx: &EngineContext) {
    if !super::require_open(ctx) {
        return;
    }
    match ctx.close() {
        Ok(()) => println!("Engine closed."),
        Err(e) => eprintln!("Failed to close engine: {e}"),
    }
}

pub fn cmd_restore(ctx: &EngineContext, args: &[&str]) {
    if !super::require_closed(ctx) {
        return;
    }
    if args.len() < 2 {
        eprintln!("Usage: restore <filename> <seed words...>");
        return;
    }
    let filename = args[0];
    let seed = args[1..].join(" ");

    let Some(mut password) = super::read_password("New engine password: ") else {
        return;
    };

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
                println!("Engine restored: {filename}");
                println!("Address: {addr}");
            } else {
                println!("Engine restored: {filename}");
            }
        }
        Err(e) => eprintln!("Failed to restore engine: {e}"),
    }
    password.zeroize();
}

pub fn cmd_refresh(ctx: &EngineContext) {
    if !super::require_open(ctx) {
        return;
    }
    println!("Refreshing...");
    match ctx.refresh() {
        Ok(()) => println!("Refresh complete. Height: {}", ctx.get_height()),
        Err(e) => eprintln!("Refresh failed: {e}"),
    }
}

pub fn cmd_save(ctx: &EngineContext) {
    if !super::require_open(ctx) {
        return;
    }
    match ctx.store() {
        Ok(()) => println!("Engine saved."),
        Err(e) => eprintln!("Failed to save engine: {e}"),
    }
}

pub fn cmd_status(ctx: &EngineContext) {
    if ctx.is_open() {
        println!("Engine: open");
        println!("Height: {}", ctx.get_height());
    } else {
        println!("Engine: not open");
    }
}

pub fn cmd_password(ctx: &EngineContext) {
    if !super::require_open(ctx) {
        return;
    }

    let Some(mut old_pw) = super::read_password("Password: ") else {
        return;
    };

    match ctx.json_rpc("get_version", "{}") {
        Ok(_) => {}
        Err(_) => {
            eprintln!("Incorrect password.");
            old_pw.zeroize();
            return;
        }
    }

    let Some(mut new_pw) = super::read_password("New password: ") else {
        old_pw.zeroize();
        return;
    };
    let Some(confirm_pw) = super::read_password("Confirm password: ") else {
        old_pw.zeroize();
        new_pw.zeroize();
        return;
    };

    if new_pw != confirm_pw {
        eprintln!("Passwords do not match.");
        old_pw.zeroize();
        new_pw.zeroize();
        return;
    }
    drop(confirm_pw);

    let params = serde_json::json!({
        "old_password": old_pw,
        "new_password": new_pw,
    });

    match ctx.json_rpc("change_wallet_password", &params.to_string()) {
        Ok(_) => println!("Password changed successfully."),
        Err(e) => eprintln!("Failed to change password: {e}"),
    }

    old_pw.zeroize();
    new_pw.zeroize();
}

pub fn cmd_rescan(ctx: &EngineContext, hard: bool) {
    if !super::require_open(ctx) {
        return;
    }

    if hard {
        eprintln!(
            "WARNING: Hard rescan will reset the engine's transaction history metadata.\n\
             Balances will be recalculated but labels and notes will be lost."
        );
        if !super::confirm_dangerous(
            "Type 'I UNDERSTAND I WILL LOSE METADATA' to confirm: ",
            "I UNDERSTAND I WILL LOSE METADATA",
        ) {
            println!("Cancelled.");
            return;
        }
    }

    let params = serde_json::json!({ "hard": hard });
    match ctx.json_rpc("rescan_blockchain", &params.to_string()) {
        Ok(_) => println!("Rescan initiated."),
        Err(e) => eprintln!("Rescan failed: {e}"),
    }
}
