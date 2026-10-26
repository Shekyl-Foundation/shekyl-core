// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The command line: `ct-dynamic [samples-per-class] [row-filter]
//! [only-fixed|only-random]`, positional, each optional in order. An empty
//! filter matches every row, so `ct-dynamic 200000 "" only-fixed` times one
//! class of every row.

use core::fmt;
use core::str::FromStr;

use crate::classes::Class;
use crate::stats::MIN_SAMPLES_PER_CLASS;

pub const USAGE: &str = "ct-dynamic [samples-per-class] [row-filter] [only-fixed|only-random]";

/// The exit status for a command line the program refuses (EX_USAGE's
/// shell convention: 2 is misuse).
pub const USAGE_EXIT_CODE: u8 = 2;

/// Batches per class: at least the statistic's floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SampleCount(usize);

impl SampleCount {
    pub const DEFAULT: SampleCount = SampleCount(20_000);

    pub fn get(self) -> usize {
        self.0
    }
}

impl FromStr for SampleCount {
    type Err = CliError;
    fn from_str(text: &str) -> Result<Self, CliError> {
        match text.parse::<usize>() {
            Ok(n) if n >= MIN_SAMPLES_PER_CLASS => Ok(SampleCount(n)),
            _ => Err(CliError::SampleCount(text.to_owned())),
        }
    }
}

/// Rows whose name contains the filter; no filter matches every row.
#[derive(Clone, Debug, Default)]
pub struct RowFilter(Option<String>);

impl RowFilter {
    pub fn admits(&self, row: &str) -> bool {
        self.0.as_deref().is_none_or(|part| row.contains(part))
    }
}

/// Which classes' batches are timed. One class alone is for running a
/// profiler (`perf stat`, a cycle-counter sampler) over that class; the t
/// statistic needs both, so a one-class run reports batch counts and the
/// wall-clock window of its timed loop, to join the profiler's samples on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassSelection {
    Both,
    Only(Class),
}

impl ClassSelection {
    pub fn times(self, class: Class) -> bool {
        match self {
            ClassSelection::Both => true,
            ClassSelection::Only(only) => only == class,
        }
    }
}

impl FromStr for ClassSelection {
    type Err = CliError;
    fn from_str(text: &str) -> Result<Self, CliError> {
        [Class::Fixed, Class::Random]
            .into_iter()
            .find(|class| text == format!("only-{}", class.label()))
            .map(ClassSelection::Only)
            .ok_or_else(|| CliError::ClassSelection(text.to_owned()))
    }
}

/// One run's settings.
#[derive(Clone, Debug)]
pub struct Config {
    pub samples: SampleCount,
    pub filter: RowFilter,
    pub classes: ClassSelection,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CliError {
    SampleCount(String),
    ClassSelection(String),
    ExtraArguments(Vec<String>),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::SampleCount(got) => write!(
                f,
                "samples per class must be an integer >= {MIN_SAMPLES_PER_CLASS}, got {got:?}"
            ),
            CliError::ClassSelection(got) => write!(
                f,
                "the third argument must be only-{} or only-{}, got {got:?}",
                Class::Fixed.label(),
                Class::Random.label()
            ),
            CliError::ExtraArguments(extra) => write!(f, "unexpected arguments {extra:?}"),
        }
    }
}

impl Config {
    /// From the arguments after the program name.
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, CliError> {
        let mut args = args.into_iter();
        let samples = args
            .next()
            .map_or(Ok(SampleCount::DEFAULT), |a| a.parse())?;
        let filter = RowFilter(args.next());
        let classes = args
            .next()
            .map_or(Ok(ClassSelection::Both), |a| a.parse())?;
        let extra: Vec<String> = args.collect();
        if !extra.is_empty() {
            return Err(CliError::ExtraArguments(extra));
        }
        Ok(Config {
            samples,
            filter,
            classes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Config, CliError> {
        Config::parse(args.iter().map(|a| a.to_string()))
    }

    #[test]
    fn no_arguments_is_the_default_run() {
        let c = parse(&[]).unwrap();
        assert_eq!(c.samples, SampleCount::DEFAULT);
        assert!(c.filter.admits("anything"));
        assert_eq!(c.classes, ClassSelection::Both);
    }

    #[test]
    fn the_sample_floor_is_enforced() {
        let below = (MIN_SAMPLES_PER_CLASS - 1).to_string();
        assert!(matches!(parse(&[&below]), Err(CliError::SampleCount(_))));
        let floor = MIN_SAMPLES_PER_CLASS.to_string();
        assert_eq!(
            parse(&[&floor]).unwrap().samples.get(),
            MIN_SAMPLES_PER_CLASS
        );
        assert!(matches!(parse(&["many"]), Err(CliError::SampleCount(_))));
    }

    #[test]
    fn an_empty_filter_admits_every_row() {
        let c = parse(&["100", "", "only-fixed"]).unwrap();
        assert!(c.filter.admits("helio square"));
        assert_eq!(c.classes, ClassSelection::Only(Class::Fixed));
        assert!(!c.classes.times(Class::Random));
    }

    #[test]
    fn a_misspelt_class_selection_is_refused_not_ignored() {
        assert!(matches!(
            parse(&["100", "helio", "only-fixd"]),
            Err(CliError::ClassSelection(_))
        ));
    }

    #[test]
    fn extra_arguments_are_refused() {
        assert!(matches!(
            parse(&["100", "helio", "only-random", "more"]),
            Err(CliError::ExtraArguments(_))
        ));
    }
}
