// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The refusals for a file the start replaces that the one replace could
//! not replace (Rick, 2026-11-18 and 2026-11-19): another program held it
//! open past the wait (`config.replace.held-open`), or its read-only
//! attribute refused the rename (`config.replace.read-only`). One builder
//! each for every caller, the data directory's marker here and the RPC's
//! files and rendezvous in `shekyl-daemon-rpc`.

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
    Diagnostic::new(Code::ReplaceHeldOpen, Source::Machine)
        .param("path", held.held.display().to_string())
        .param(
            "cause",
            format!(
                "another program, most likely an antivirus scanner or a search indexer, held it \
                 open for more than {wait} s"
            ),
        )
        .param("remedy", format!("exclude {} from scanning", dir.display()))
        .param("wait", wait.to_string())
        .param("dir", dir.display().to_string())
}

/// The refusal for a file whose read-only attribute refused its replace
/// (`config.replace.read-only`): the file.
#[must_use]
pub fn read_only_refusal(path: &std::path::Path) -> Diagnostic {
    Diagnostic::new(Code::ReplaceReadOnly, Source::Machine)
        .param("path", path.display().to_string())
}

#[cfg(test)]
mod held_open_tests {
    use std::path::{Path, PathBuf};

    use shekyl_os_account::private_file::HeldOpen;

    use super::{held_open_refusal, read_only_refusal};

    /// The two ways a replace is refused read as two sentences, each with
    /// its own remedy (Rick, 2026-11-19): a held file names the program and
    /// the wait, and the directory to exclude from scanning; a read-only
    /// one names the attribute to clear, and nothing about scanning. Red
    /// edit: fold the read-only file into the held-open refusal's cause, and
    /// its code and remedy are the scanner's.
    #[test]
    fn a_held_file_and_a_read_only_file_are_refused_apart() {
        let held = held_open_refusal(
            &HeldOpen {
                held: PathBuf::from("rendezvous/shekyl-record"),
                live: PathBuf::from("rendezvous/shekyl-record"),
            },
            Path::new("rendezvous"),
        )
        .render();
        assert!(
            held.starts_with(
                "rendezvous/shekyl-record could not be written: another program, most likely an \
                 antivirus scanner or a search indexer, held it open for more than 2 s; exclude \
                 rendezvous from scanning and start the daemon again"
            ),
            "{held}"
        );
        let read_only = read_only_refusal(Path::new("rendezvous/shekyl-record")).render();
        assert!(
            read_only.starts_with(
                "rendezvous/shekyl-record could not be written: it is read-only; clear its \
                 read-only attribute and start the daemon again"
            ),
            "{read_only}"
        );
        assert!(
            read_only.contains("[config.replace.read-only"),
            "{read_only}"
        );
    }
}
