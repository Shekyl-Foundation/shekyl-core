// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Whether a sink's lines carry colour.
//!
//! Stderr is [`LineColour::Ansi`] only when it is a terminal and
//! [`NoColor`] is inactive. Every other sink is [`LineColour::Plain`].
//! That is the same rule as `epee::set_console_color`: colour when the
//! stream is a terminal and `NO_COLOR` is unset or empty.

/// no-color.org's variable. IG-13 permits this read: it changes rendering,
/// never a value.
const NO_COLOR_ENV: &str = "NO_COLOR";

/// `NO_COLOR` as no-color.org and `epee::is_nocolor` read it.
///
/// Unset and empty leave colour available. Any other value suppresses it,
/// including `"0"` and a value that is not Unicode. `getenv` still sees
/// those bytes, and any non-empty value suppresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NoColor {
    /// Unset, or set to an empty string.
    Inactive,
    /// Set to a non-empty value.
    Suppress,
}

impl NoColor {
    /// `value` is the variable's text. `None` is unset.
    pub(crate) fn from_text(value: Option<&str>) -> Self {
        match value {
            None | Some("") => Self::Inactive,
            Some(_) => Self::Suppress,
        }
    }

    /// Classify one read of [`NO_COLOR_ENV`].
    pub(crate) fn from_var(result: &Result<String, std::env::VarError>) -> Self {
        match result {
            Ok(value) => Self::from_text(Some(value)),
            Err(std::env::VarError::NotPresent) => Self::Inactive,
            Err(std::env::VarError::NotUnicode(_)) => Self::Suppress,
        }
    }

    /// The process's `NO_COLOR`.
    pub(crate) fn from_env() -> Self {
        Self::from_var(&std::env::var(NO_COLOR_ENV))
    }
}

/// How a sink renders its lines.
///
/// [`Ansi`](Self::Ansi) wraps the timestamp, level, and target in colour
/// codes. [`Plain`](Self::Plain) does not. Production stderr is
/// [`stderr`](Self::stderr). The file sink is [`Plain`](Self::Plain).
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineColour {
    /// No escape bytes.
    Plain,
    /// ANSI colour codes.
    Ansi,
}

impl LineColour {
    /// Stderr's colour. A non-terminal is always [`Plain`](Self::Plain).
    /// A terminal is [`Ansi`](Self::Ansi) only while `no_color` is
    /// [`NoColor::Inactive`].
    pub(crate) const fn stderr(is_terminal: bool, no_color: NoColor) -> Self {
        if is_terminal {
            match no_color {
                NoColor::Inactive => Self::Ansi,
                NoColor::Suppress => Self::Plain,
            }
        } else {
            Self::Plain
        }
    }

    /// The flag [`tracing_subscriber::fmt::Layer::with_ansi`] takes.
    pub(crate) const fn ansi(self) -> bool {
        match self {
            Self::Ansi => true,
            Self::Plain => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LineColour, NoColor};

    #[test]
    fn stderr_is_coloured_only_for_a_terminal_with_no_color_inactive() {
        assert_eq!(
            LineColour::stderr(false, NoColor::Inactive),
            LineColour::Plain,
            "a pipe or the journal is plain"
        );
        assert_eq!(
            LineColour::stderr(false, NoColor::Suppress),
            LineColour::Plain,
            "NO_COLOR cannot turn a non-terminal into colour"
        );
        assert_eq!(
            LineColour::stderr(true, NoColor::Suppress),
            LineColour::Plain,
            "a terminal with NO_COLOR set is plain"
        );
        assert_eq!(
            LineColour::stderr(true, NoColor::Inactive),
            LineColour::Ansi,
            "a terminal with NO_COLOR inactive is coloured"
        );
    }

    #[test]
    fn the_ansi_flag_is_the_variant() {
        assert!(!LineColour::Plain.ansi());
        assert!(LineColour::Ansi.ansi());
    }

    #[test]
    fn no_color_suppresses_only_a_non_empty_value() {
        assert_eq!(NoColor::from_text(None), NoColor::Inactive);
        assert_eq!(NoColor::from_text(Some("")), NoColor::Inactive);
        assert_eq!(NoColor::from_text(Some("1")), NoColor::Suppress);
        assert_eq!(NoColor::from_text(Some("0")), NoColor::Suppress);
        assert_eq!(NoColor::from_text(Some(" ")), NoColor::Suppress);
    }

    #[test]
    fn a_missing_no_color_is_inactive_and_a_non_unicode_one_suppresses() {
        assert_eq!(
            NoColor::from_var(&Err(std::env::VarError::NotPresent)),
            NoColor::Inactive
        );
        assert_eq!(NoColor::from_var(&Ok(String::new())), NoColor::Inactive);
        assert_eq!(NoColor::from_var(&Ok("0".to_owned())), NoColor::Suppress);

        // Unix can store a non-Unicode value. `getenv` still sees the
        // bytes, and `epee::is_nocolor` suppresses on any non-empty
        // string, so this read does too.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let value = std::ffi::OsString::from_vec(vec![0xff]);
            assert_eq!(
                NoColor::from_var(&Err(std::env::VarError::NotUnicode(value))),
                NoColor::Suppress
            );
        }
    }
}
