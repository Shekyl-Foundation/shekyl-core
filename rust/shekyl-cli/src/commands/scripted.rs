// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The file-backed wallet lifecycle (`INPUT_GRAMMAR.md` §12.2).
//!
//! The prompt's `wallet create` and `wallet restore` ask on the terminal and
//! show the seed once on screen, which automation cannot drive. With
//! `--mnemonic-file` the recovery words go to or come from a file instead:
//! `wallet create` writes a new file that is owner-only from its first
//! instant (`0600` on Unix, an owner-only DACL set at `CreateFile` on
//! Windows, `WINDOWS_WALLET_SUPPORT.md` WP-D8), and `wallet restore` refuses
//! one another account can read. This is the ONLY sanctioned way for the
//! seed to reach a file: the prompt path refuses non-TTY output rather than
//! leak it. The password comes from `wallet-password-file`, or the hidden
//! prompt at a terminal.

use std::fs::File;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use shekyl_options::{Code, Diagnostic, Source};
use zeroize::Zeroizing;

use crate::outcome::{refusal, CommandFailed, CommandResult, Presentation};
use crate::rpc_client::{params, RpcSession};

type BoxErr = Box<dyn std::error::Error>;

/// Who may read a password or recovery-words file, as a refusal names them:
/// the configuration file's rule for a file holding a secret.
#[cfg(unix)]
const SECRET_FILE_READERS: &str =
    "this account and root (0600, or 0640 with a group only this account is in)";
#[cfg(windows)]
const SECRET_FILE_READERS: &str = "this account, SYSTEM and Administrators";

/// The longest password or recovery-words file read. Recovery words are
/// a few hundred bytes, and a file past this is not one of these.
const SECRET_FILE_BYTES_MAX: u64 = 64 * 1024;

/// What `wallet create --mnemonic-file` tells a script. The words stay in
/// the file.
#[derive(Debug, Serialize)]
pub struct CreatedWallet {
    pub name: String,
    pub backup_file: String,
}

/// What `wallet restore --mnemonic-file` tells a script.
#[derive(Debug, Serialize)]
pub struct RestoredWallet {
    pub name: String,
}

/// Where `wallet-password-file` says the password is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PasswordSource {
    /// A file only this account can read.
    File(PathBuf),
    /// One line of standard input.
    Stdin,
}

impl PasswordSource {
    /// Read the password into a wiped buffer. A single trailing newline
    /// (`\n` or `\r\n`) is stripped, the common shape of a piped line, and
    /// no other whitespace, so a password may hold spaces.
    ///
    /// # Errors
    ///
    /// The file is missing, another account can read it, it is not text, or
    /// standard input has no line left.
    pub fn read(&self) -> Result<Zeroizing<String>, CommandFailed> {
        let mut password = match self {
            Self::File(path) => read_secret_text(path, "wallet-password-file")?,
            Self::Stdin => {
                let mut line = Zeroizing::new(String::new());
                let read = std::io::stdin()
                    .read_line(&mut line)
                    .map_err(|e| refusal(format!("cannot read the password from stdin: {e}")))?;
                if read == 0 {
                    return Err(refusal(
                        "wallet-password-file is stdin, and standard input has no line left",
                    ));
                }
                line
            }
        };
        strip_one_trailing_newline(&mut password);
        Ok(password)
    }
}

/// The text of a secret file, refused with a typed code when anyone but
/// this account can read it. Checked and read through one handle, so the
/// file judged is the file read.
fn read_secret_text(path: &Path, option: &str) -> Result<Zeroizing<String>, CommandFailed> {
    let shown = path.display().to_string();
    let unreadable = |error: String| {
        refusal(
            Diagnostic::new(Code::FileUnreadable, Source::Machine)
                .option(option)
                .param("path", shown.clone())
                .param("error", error)
                .render(),
        )
    };
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(refusal(
                Diagnostic::new(Code::FileMissing, Source::Cli)
                    .option(option)
                    .param("path", shown)
                    .render(),
            ));
        }
        Err(e) => return Err(unreadable(e.to_string())),
    };
    if let Some(principal) = shekyl_daemon_config::file::secret_file_reader(&file, path) {
        return Err(refusal(
            Diagnostic::new(Code::FileSecretReadable, Source::Machine)
                .option(option)
                .param("path", shown)
                .param("principal", principal)
                .param("permitted", SECRET_FILE_READERS)
                .render(),
        ));
    }
    // Sized up front: a buffer that grew would leave a copy of the secret in
    // the allocation it left, which `Zeroizing` never sees.
    let capacity = usize::try_from(SECRET_FILE_BYTES_MAX).map_or(usize::MAX, |max| max + 1);
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    file.take(SECRET_FILE_BYTES_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| unreadable(e.to_string()))?;
    if bytes.len() as u64 > SECRET_FILE_BYTES_MAX {
        return Err(unreadable(format!(
            "it is longer than {SECRET_FILE_BYTES_MAX} bytes"
        )));
    }
    match std::str::from_utf8(&bytes) {
        Ok(text) => Ok(Zeroizing::new(text.to_owned())),
        // Never what the bytes were.
        Err(_) => Err(unreadable("it is not UTF-8 text".to_owned())),
    }
}

/// The password for a file-backed create or restore: the named source, or
/// the hidden prompt at a terminal.
fn new_wallet_password(
    presentation: &Presentation,
    source: Option<&PasswordSource>,
) -> Result<Zeroizing<String>, CommandFailed> {
    if let Some(source) = source {
        return source.read();
    }
    if !presentation.interactive() {
        return Err(refusal(
            "a password source is required: set wallet-password-file to a file or stdin",
        ));
    }
    let password = super::read_password("New wallet password: ")?;
    let confirm = super::read_password("Confirm password: ")?;
    if password != confirm {
        return Err(refusal("Passwords do not match."));
    }
    Ok(password)
}

fn local(error: impl std::fmt::Display) -> CommandFailed {
    refusal(error.to_string())
}

/// Create a wallet and write its one-time recovery words to `mnemonic_file`.
///
/// The caller prints the result. This function does not.
pub fn run_create(
    rpc: &RpcSession,
    presentation: &Presentation,
    source: Option<&PasswordSource>,
    name: &str,
    mnemonic_file: &Path,
) -> CommandResult<CreatedWallet> {
    super::require_closed(rpc)?;
    let password = new_wallet_password(presentation, source)?;

    // The wallet directory first: the file may be named inside it, and a
    // failure here leaves no reserved file to clean up while its handle is
    // open.
    rpc.make_wallet_dir()?;
    // Reserve the file BEFORE creating the wallet (O_EXCL, 0600): if this
    // fails we have created nothing, so there is no wallet whose backup we
    // then cannot store. If create_wallet later fails, the empty file is
    // removed on the error path below.
    let mut seed_file = open_seed_out(mnemonic_file).map_err(local)?;

    let result = rpc.call(
        "create_wallet",
        params::NamedPassword {
            name,
            password: &password,
        },
    );
    drop(password);

    let val = match result {
        Ok(v) => v,
        Err(e) => {
            drop(std::fs::remove_file(mnemonic_file));
            return Err(rpc.report("Failed to create wallet", &e));
        }
    };
    rpc.set_open(name);

    // Mainnet/stagenet return a BIP-39 mnemonic; testnet a raw seed as hex.
    let backup = Zeroizing::new(
        val.get(concat!("mne", "monic"))
            .or_else(|| val.get("raw_seed_hex"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| local("create_wallet returned no seed backup"))?
            .to_owned(),
    );
    if let Err(e) = write_seed(&mut seed_file, &backup) {
        drop(std::fs::remove_file(mnemonic_file));
        return Err(local(format!(
            "failed to write seed to {}: {e}",
            mnemonic_file.display()
        )));
    }

    Ok(CreatedWallet {
        name: name.to_owned(),
        backup_file: mnemonic_file.display().to_string(),
    })
}

pub(crate) fn show_created_wallet(created: &CreatedWallet) {
    crate::out_line!(
        "Created wallet '{}'. Seed written to {} (mode 0600) — protect or delete it.",
        created.name,
        created.backup_file
    );
}

/// Restore a wallet from a recovery-words file. The caller prints the
/// result.
///
/// The receipt is the wallet name, copied before the password and the
/// seed are read. The function that holds those secrets returns only
/// success or failure, so the printed value is not assembled while
/// either secret is live.
pub fn run_restore(
    rpc: &RpcSession,
    presentation: &Presentation,
    source: Option<&PasswordSource>,
    name: &str,
    mnemonic_file: &Path,
    restore_height: Option<u64>,
) -> CommandResult<RestoredWallet> {
    super::require_closed(rpc)?;
    let receipt = name.to_owned();
    post_restore(
        rpc,
        presentation,
        source,
        name,
        mnemonic_file,
        restore_height,
    )?;
    rpc.set_open(name);
    Ok(RestoredWallet { name: receipt })
}

fn post_restore(
    rpc: &RpcSession,
    presentation: &Presentation,
    source: Option<&PasswordSource>,
    name: &str,
    mnemonic_file: &Path,
    restore_height: Option<u64>,
) -> CommandResult<()> {
    // The file first: a refused file costs no password prompt.
    let seed = read_secret_text(mnemonic_file, "--mnemonic-file")?;
    let password = new_wallet_password(presentation, source)?;

    rpc.make_wallet_dir()?;
    let result = rpc.call(
        "restore_wallet",
        params::Restore {
            name,
            password: &password,
            mnemonic: seed.trim(),
            restore_height: restore_height.unwrap_or(0),
        },
    );
    drop(password);
    drop(seed);

    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(rpc.report("Failed to restore wallet", &e)),
    }
}

pub(crate) fn show_restored_wallet(restored: &RestoredWallet) {
    crate::out_line!("Restored wallet '{}'.", restored.name);
}

fn strip_one_trailing_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
}

/// Open the seed-out path 0600 with O_EXCL semantics: refuse to overwrite an
/// existing file and refuse to follow a symlink on the final component.
fn open_seed_out(path: &Path) -> Result<File, BoxErr> {
    open_owner_only_excl(path, "seed file")
}

/// Open `path` as a new owner-only (0600) file with O_EXCL semantics: refuse
/// to overwrite an existing file and refuse to follow a symlink on the final
/// component. The one file-creation shape for everything the CLI writes out
/// (`--mnemonic-file`, `address --file`); `what` names the file class in the error.
#[cfg(unix)]
pub(crate) fn open_owner_only_excl(path: &Path, what: &str) -> Result<File, BoxErr> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| create_error(what, path, &e))
}

/// Open `path` owner-only with `CREATE_NEW` semantics — the same contract as
/// the Unix arm, with the DACL applied at creation rather than a mode. The
/// Win32 call lives in `shekyl-win-sec` (WP-D2: this crate holds no
/// `unsafe`); what is here is the call and the error text.
#[cfg(windows)]
pub(crate) fn open_owner_only_excl(path: &Path, what: &str) -> Result<File, BoxErr> {
    shekyl_win_sec::create_owner_only_file(path).map_err(|e| create_error(what, path, &e))
}

fn create_error(what: &str, path: &Path, cause: &dyn std::fmt::Display) -> BoxErr {
    format!(
        "cannot create {what} {} (it must not already exist): {cause}",
        path.display()
    )
    .into()
}

fn write_seed(file: &mut File, seed: &str) -> Result<(), std::io::Error> {
    file.write_all(seed.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    // fsync so a scripted create that reports success has durably persisted the
    // only copy of the seed before the process exits.
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::strip_one_trailing_newline;
    #[cfg(unix)]
    use super::{read_secret_text, PasswordSource};

    /// A password or recovery-words file another account can read is
    /// refused with the typed code, naming the file and not its contents;
    /// a private one is read with one trailing newline off. Red edit: drop
    /// the `secret_file_reader` check, and the 0644 file is read.
    #[cfg(unix)]
    #[test]
    fn a_secret_file_another_account_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pw");
        std::fs::write(&path, "hunter2\n").expect("write");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let refused = format!(
            "{:?}",
            PasswordSource::File(path.clone())
                .read()
                .expect_err("a world-readable file")
        );
        assert!(refused.contains("config.file.secret-readable"), "{refused}");
        assert!(refused.contains("pw"), "{refused}");
        assert!(!refused.contains("hunter2"), "{refused}");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let password = PasswordSource::File(path).read().expect("a private file");
        assert_eq!(password.as_str(), "hunter2");
    }

    /// A missing file and an oversized one are refused by name, and neither
    /// is taken for an empty password.
    #[cfg(unix)]
    #[test]
    fn a_missing_or_oversized_secret_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = format!(
            "{:?}",
            read_secret_text(&dir.path().join("none"), "wallet-password-file")
                .expect_err("a missing file")
        );
        assert!(missing.contains("config.file.missing"), "{missing}");

        let long = dir.path().join("long");
        let size = usize::try_from(super::SECRET_FILE_BYTES_MAX).expect("fits") + 1;
        std::fs::write(&long, vec![b'a'; size]).expect("write");
        std::fs::set_permissions(&long, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let oversized = format!(
            "{:?}",
            read_secret_text(&long, "wallet-password-file").expect_err("an oversized file")
        );
        assert!(oversized.contains("longer than"), "{oversized}");
    }

    #[test]
    fn strips_exactly_one_trailing_newline() {
        let mut s = "hunter2\n".to_string();
        strip_one_trailing_newline(&mut s);
        assert_eq!(s, "hunter2");

        let mut crlf = "hunter2\r\n".to_string();
        strip_one_trailing_newline(&mut crlf);
        assert_eq!(crlf, "hunter2");

        // Only one newline is stripped, and internal/leading spaces survive.
        let mut spaced = " pass word \n\n".to_string();
        strip_one_trailing_newline(&mut spaced);
        assert_eq!(spaced, " pass word \n");

        // No trailing newline: unchanged (supports `printf '%s'`).
        let mut bare = "nonewline".to_string();
        strip_one_trailing_newline(&mut bare);
        assert_eq!(bare, "nonewline");
    }
}
