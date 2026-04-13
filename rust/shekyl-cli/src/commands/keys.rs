// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Key display commands: seed, viewkey, spendkey, export/import key images.
//! Terminal safety (display.rs) is applied to all secret-displaying commands.

use crate::wallet::WalletContext;

pub fn cmd_seed(ctx: &WalletContext) {
    if !super::require_open(ctx) {
        return;
    }

    eprintln!(
        "WARNING: Your mnemonic seed grants full access to your funds.\n\
         Never share it. Never enter it on a website."
    );

    if !super::confirm("Display seed?") {
        println!("Cancelled.");
        return;
    }

    match ctx.query_key("mnemonic") {
        Ok(val) => {
            if let Some(key) = val.get("key").and_then(|k| k.as_str()) {
                let mut secret = key.to_string();
                if let Err(e) = crate::display::display_secret("Mnemonic seed", &mut secret) {
                    eprintln!("{e}");
                }
            } else {
                eprintln!("Unexpected response format.");
            }
        }
        Err(e) => eprintln!("Failed to retrieve seed: {e}"),
    }
}

pub fn cmd_viewkey(ctx: &WalletContext) {
    if !super::require_open(ctx) {
        return;
    }

    eprintln!("WARNING: The secret view key allows monitoring all incoming transactions.");

    if !super::confirm("Display view key?") {
        println!("Cancelled.");
        return;
    }

    match ctx.query_key("view_key") {
        Ok(val) => {
            if let Some(key) = val.get("key").and_then(|k| k.as_str()) {
                let mut secret = key.to_string();
                if let Err(e) = crate::display::display_secret("Secret view key", &mut secret) {
                    eprintln!("{e}");
                }
            } else {
                eprintln!("Unexpected response format.");
            }
        }
        Err(e) => eprintln!("Failed to retrieve view key: {e}"),
    }
}

pub fn cmd_spendkey(ctx: &WalletContext) {
    if !super::require_open(ctx) {
        return;
    }

    eprintln!(
        "WARNING: The secret spend key grants FULL control of your funds.\n\
         Anyone with this key can spend your entire balance."
    );

    let addr_prefix = match ctx.get_address(0) {
        Ok(val) => val
            .get("address")
            .and_then(|a| a.as_str())
            .map(|a| a.chars().take(8).collect::<String>())
            .unwrap_or_default(),
        Err(_) => String::new(),
    };

    if addr_prefix.is_empty() {
        if !super::confirm("Display spend key?") {
            println!("Cancelled.");
            return;
        }
    } else {
        let prompt = format!(
            "Type the first 8 characters of your primary address to confirm ({addr_prefix}): "
        );
        if !super::confirm_dangerous(&prompt, &addr_prefix) {
            println!("Cancelled.");
            return;
        }
    }

    match ctx.query_key("spend_key") {
        Ok(val) => {
            if let Some(key) = val.get("key").and_then(|k| k.as_str()) {
                let mut secret = key.to_string();
                if let Err(e) = crate::display::display_secret("Secret spend key", &mut secret) {
                    eprintln!("{e}");
                }
            } else {
                eprintln!("Unexpected response format.");
            }
        }
        Err(e) => eprintln!("Failed to retrieve spend key: {e}"),
    }
}

pub fn cmd_export_key_images(
    ctx: &WalletContext,
    filename: &str,
    all: bool,
    _since_height: Option<u64>,
    _account_index: u32,
) {
    if !super::require_open(ctx) {
        return;
    }

    let params = serde_json::json!({ "all": all });
    match ctx.json_rpc("export_key_images", &params.to_string()) {
        Ok(val) => {
            let data = serde_json::to_string_pretty(&val).unwrap_or_default();

            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;

                if let Some(parent) = std::path::Path::new(filename).parent() {
                    if let Ok(meta) = std::fs::metadata(parent) {
                        use std::os::unix::fs::PermissionsExt;
                        let mode = meta.permissions().mode();
                        if mode & 0o077 != 0 {
                            eprintln!(
                                "WARNING: Parent directory has group/world permissions (mode {:o}). \
                                 Key image file may be accessible to other users.",
                                mode
                            );
                        }
                    }
                }

                match std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(filename)
                {
                    Ok(mut f) => {
                        if let Err(e) = f.write_all(data.as_bytes()) {
                            eprintln!("Failed to write key images: {e}");
                        } else {
                            println!("Key images exported to {filename} (mode 0600).");
                        }
                    }
                    Err(e) => eprintln!("Failed to create file: {e}"),
                }
            }

            #[cfg(not(unix))]
            {
                if let Err(e) = std::fs::write(filename, &data) {
                    eprintln!("Failed to write key images: {e}");
                } else {
                    println!("Key images exported to {filename}.");
                }
            }
        }
        Err(e) => eprintln!("Failed to export key images: {e}"),
    }
}

pub fn cmd_import_key_images(ctx: &WalletContext, filename: &str) {
    if !super::require_open(ctx) {
        return;
    }

    let data = match std::fs::read_to_string(filename) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read {filename}: {e}");
            return;
        }
    };

    let parsed: serde_json::Value = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("File is not valid JSON: {e}. Unrecognized format.");
            return;
        }
    };

    let signed_key_images = match parsed.get("signed_key_images").and_then(|s| s.as_array()) {
        Some(arr) => arr.clone(),
        None => {
            eprintln!("File does not contain 'signed_key_images' field. Unrecognized format.");
            return;
        }
    };

    let params = serde_json::json!({
        "signed_key_images": signed_key_images,
    });

    match ctx.json_rpc("import_key_images", &params.to_string()) {
        Ok(val) => {
            let height = val.get("height").and_then(|h| h.as_u64()).unwrap_or(0);
            let spent = val.get("spent").and_then(|s| s.as_u64()).unwrap_or(0);
            let unspent = val.get("unspent").and_then(|u| u.as_u64()).unwrap_or(0);
            println!("Key images imported. Height: {height}");
            println!(
                "  Spent: {} SKL, Unspent: {} SKL",
                super::format_amount(spent),
                super::format_amount(unspent)
            );
        }
        Err(e) => eprintln!("Failed to import key images: {e}"),
    }
}
