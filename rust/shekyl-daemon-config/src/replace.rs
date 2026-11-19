// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The refusal for a file the start replaces that another program held open
//! past the one replace's wait (`config.replace.held-open`; Rick,
//! 2026-11-18): one builder for every caller, the data directory's marker
//! here and the RPC's files and rendezvous in `shekyl-daemon-rpc`.

use shekyl_options::{Code, Diagnostic, Source};

/// The refusal for a file another program held open past the wait
/// (`config.replace.held-open`): the file, the wait, and `dir`, the
/// directory to exclude from scanning (the data directory, or the
/// rendezvous directory for the owner's record).
#[must_use]
pub fn held_open_refusal(
    held: &shekyl_os_account::private_file::HeldOpen,
    dir: &std::path::Path,
) -> Diagnostic {
    let wait = shekyl_os_account::private_file::REPLACE_WAIT.as_secs();
    let (or_unwritable, or_make_writable) = if held.or_unwritable {
        (", or it is not writable", ", or make it writable,")
    } else {
        ("", "")
    };
    Diagnostic::new(Code::ReplaceHeldOpen, Source::Machine)
        .param("path", held.held.display().to_string())
        .param(
            "cause",
            format!(
                "another program, most likely an antivirus scanner or a search indexer, held it \
             open for more than {wait} s{or_unwritable}"
            ),
        )
        .param(
            "remedy",
            format!("exclude {} from scanning{or_make_writable}", dir.display()),
        )
        .param("wait", wait.to_string())
        .param("dir", dir.display().to_string())
}

#[cfg(test)]
mod held_open_tests {
    use std::path::{Path, PathBuf};

    use shekyl_os_account::private_file::HeldOpen;

    use super::held_open_refusal;

    /// `config.replace.held-open` reads as one sentence whether or not the
    /// file may instead be unwritable: the cause names the program and the
    /// wait, the remedy the directory, and the unwritable branch adds its
    /// own clause to each. Red edit: end the unwritable cause with a comma,
    /// and the sentence reads "not writable, for more than 2 s" (Copilot,
    /// #1439).
    #[test]
    fn the_held_open_refusal_reads_in_both_branches() {
        let render = |or_unwritable| {
            held_open_refusal(
                &HeldOpen {
                    held: PathBuf::from("rendezvous/shekyl-record"),
                    live: PathBuf::from("rendezvous/shekyl-record"),
                    or_unwritable,
                },
                Path::new("rendezvous"),
            )
            .render()
        };
        let held = render(false);
        assert!(
            held.starts_with(
                "rendezvous/shekyl-record could not be written: another program, most likely an \
                 antivirus scanner or a search indexer, held it open for more than 2 s; exclude \
                 rendezvous from scanning and start the daemon again"
            ),
            "{held}"
        );
        let unwritable = render(true);
        assert!(
            unwritable.starts_with(
                "rendezvous/shekyl-record could not be written: another program, most likely an \
                 antivirus scanner or a search indexer, held it open for more than 2 s, or it is \
                 not writable; exclude rendezvous from scanning, or make it writable, and start \
                 the daemon again"
            ),
            "{unwritable}"
        );
    }
}
