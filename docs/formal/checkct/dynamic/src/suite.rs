// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The rows, section by section. Field rows are data: a field, an operation
//! and a design, named by one rule (`[prefix: ]<field> <operation>[ suffix]`)
//! and run by one dispatcher, so both fields always get the same rows and
//! every contrast of an operation runs the same code. Record files cite
//! rows by name, so a name is a stable identifier: the catalogue test below
//! checks that every name a committed record cites still exists.

use core::hint::black_box;

use crypto_bigint::{Encoding, U256};
use dalek_ff_group::FieldElement as Field25519;
use helioselene::HelioseleneField;

use crate::classes::Contrast;
use crate::field::{decode, sink_word, FieldUnderTest};
use crate::harness::Bench;
use crate::operand::{Canonical, FromShape, Residue25519, Sample, Shape};
use crate::rng::Rng;

/// The suffix that names a row's equal-familiarity companion.
const FIXED_PAIR_SUFFIX: &str = "[fixed-pair]";

#[derive(Clone, Copy, Debug)]
enum FieldId {
    Fe25519,
    Helio,
}

impl FieldId {
    const ALL: [FieldId; 2] = [FieldId::Fe25519, FieldId::Helio];

    /// The heading of the field's section of test rows.
    fn heading(self) -> &'static str {
        match self {
            FieldId::Fe25519 => "helioselene::Field25519 (dalek_ff_group::FieldElement)",
            FieldId::Helio => "helioselene::HelioseleneField",
        }
    }
}

/// The operations every field runs. `mul` and `square` run on two code
/// paths, because what the timer sees depends on how the operation is
/// compiled into the timed loop: `Mul`/`Square` call the non-inlined
/// wrappers (one addressable symbol per field), `MulDirect`/`SquareDirect`
/// call the field's operator in the loop itself, inlined where the field's
/// crate allows it (`HelioseleneField`'s are; dalek-ff-group's
/// `FieldElement` operators are out-of-line calls either way). Every
/// contrast runs on both, so a difference between them is a property of
/// the code path, not of the contrast.
#[derive(Clone, Copy, Debug)]
enum FieldOp {
    Add,
    Sub,
    Mul,
    MulDirect,
    Square,
    SquareDirect,
    Invert,
    Sqrt,
    Pow,
    FromRepr,
    WideReduce,
}

impl FieldOp {
    const ALL: [FieldOp; 11] = [
        FieldOp::Add,
        FieldOp::Sub,
        FieldOp::Mul,
        FieldOp::MulDirect,
        FieldOp::Square,
        FieldOp::SquareDirect,
        FieldOp::Invert,
        FieldOp::Sqrt,
        FieldOp::Pow,
        FieldOp::FromRepr,
        FieldOp::WideReduce,
    ];

    fn label(self) -> &'static str {
        match self {
            FieldOp::Add => "add",
            FieldOp::Sub => "sub",
            FieldOp::Mul => "mul",
            FieldOp::MulDirect => "mul (direct)",
            FieldOp::Square => "square",
            FieldOp::SquareDirect => "square (direct)",
            FieldOp::Invert => "invert",
            FieldOp::Sqrt => "sqrt",
            FieldOp::Pow => "pow (secret exponent)",
            FieldOp::FromRepr => "from_repr",
            FieldOp::WideReduce => "wide_reduce",
        }
    }
}

/// A field row's contrast, before its operand type is known.
#[derive(Clone, Copy, Debug)]
enum Design {
    FixedSet,
    FixedPair,
    Null,
    Constant,
    Shaped(Shape),
}

impl Design {
    /// The test designs: every test row runs with its companion.
    const TEST: [Design; 2] = [Design::FixedSet, Design::FixedPair];

    fn row_name(self, field: &str, op: FieldOp) -> String {
        let row = format!("{field} {}", op.label());
        match self {
            Design::FixedSet => row,
            Design::FixedPair => companion(&row),
            Design::Null => format!("null: {row}"),
            Design::Constant => format!("constant: {row}"),
            Design::Shaped(shape) => format!("property: {row} {}", shape.label()),
        }
    }

    /// The typed contrast; a constant is drawn from `constants`.
    fn contrast<F, I>(self, constants: &mut Rng) -> Contrast<I>
    where
        I: Sample + FromShape<F> + 'static,
    {
        match self {
            Design::FixedSet => Contrast::FixedSet,
            Design::FixedPair => Contrast::FixedPair,
            Design::Null => Contrast::Null,
            Design::Constant => Contrast::Constant(I::sample(constants)),
            Design::Shaped(shape) => {
                Contrast::Shaped(Box::new(move |rng: &mut Rng| I::from_shape(shape, rng)))
            }
        }
    }
}

fn companion(row: &str) -> String {
    format!("{row} {FIXED_PAIR_SUFFIX}")
}

/// One field row on either field.
fn field_row(h: &mut impl Bench, field: FieldId, design: Design, op: FieldOp, constants: &mut Rng) {
    match field {
        FieldId::Fe25519 => field_row_on::<Field25519>(h, design, op, constants),
        FieldId::Helio => field_row_on::<HelioseleneField>(h, design, op, constants),
    }
}

/// One field row: the operation's single code path, under `design`.
fn field_row_on<F: FieldUnderTest + 'static>(
    h: &mut impl Bench,
    design: Design,
    op: FieldOp,
    constants: &mut Rng,
) {
    let name = &design.row_name(F::LABEL, op);
    match op {
        FieldOp::Add => {
            operands::<F, (F, F)>(h, name, design, constants, |(a, b)| sink_word(&(*a + *b)))
        }
        FieldOp::Sub => {
            operands::<F, (F, F)>(h, name, design, constants, |(a, b)| sink_word(&(*a - *b)))
        }
        FieldOp::Mul => operands::<F, (F, F)>(h, name, design, constants, |(a, b)| {
            sink_word(&F::mul_isolated(a, b))
        }),
        FieldOp::MulDirect => {
            operands::<F, (F, F)>(h, name, design, constants, |(a, b)| sink_word(&(*a * *b)))
        }
        FieldOp::Square => operands::<F, F>(h, name, design, constants, |a| {
            sink_word(&F::square_isolated(a))
        }),
        FieldOp::SquareDirect => {
            operands::<F, F>(h, name, design, constants, |a| sink_word(&a.square()))
        }
        FieldOp::Invert => operands::<F, F>(h, name, design, constants, |a| {
            sink_word(&a.invert().unwrap_or(F::ZERO))
        }),
        FieldOp::Sqrt => operands::<F, F>(h, name, design, constants, |a| {
            sink_word(&a.sqrt().unwrap_or(F::ZERO))
        }),
        FieldOp::Pow => operands::<F, (F, F)>(h, name, design, constants, |(a, e)| {
            sink_word(&a.pow_secret(e))
        }),
        FieldOp::FromRepr => operands::<F, [u8; 32]>(h, name, design, constants, |encoding| {
            sink_word(&decode::<F>(*encoding))
        }),
        FieldOp::WideReduce => operands::<F, [u8; 64]>(h, name, design, constants, |bytes| {
            sink_word(&F::wide_reduce(*bytes))
        }),
    }
}

/// A field row on operands of type `I`, drawn uniformly ([`Sample`]) for
/// the random class. `op` stays a generic closure, so the timed loop is
/// monomorphised over it and calls it directly.
fn operands<F, I>(
    h: &mut impl Bench,
    name: &str,
    design: Design,
    constants: &mut Rng,
    op: impl FnMut(&I) -> u64,
) where
    I: Clone + Sample + FromShape<F> + 'static,
{
    h.row(name, design.contrast::<F, I>(constants), I::sample, op);
}

/// A test row and its companion, for rows outside the field table.
fn tested<I: Clone>(
    h: &mut impl Bench,
    name: &str,
    draw: impl Fn(&mut Rng) -> I + Copy,
    op: impl FnMut(&I) -> u64 + Copy,
) {
    h.row(name, Contrast::FixedSet, draw, op);
    h.row(&companion(name), Contrast::FixedPair, draw, op);
}

/// The operations of the null rows: the ones CA-2 is about, on both code
/// paths.
const NULL_ROW_OPS: [FieldOp; 4] = [
    FieldOp::Mul,
    FieldOp::MulDirect,
    FieldOp::Square,
    FieldOp::SquareDirect,
];

/// The operations of the constant-operand rows.
const CONSTANT_ROW_OPS: [FieldOp; 5] = [
    FieldOp::Square,
    FieldOp::SquareDirect,
    FieldOp::Mul,
    FieldOp::MulDirect,
    FieldOp::Sqrt,
];

/// The operations of the operand-property rows, each run on every shape:
/// both paths of `square`, and `sqrt`, whose out-of-line body is itself a
/// loop of inlined field operations.
const PROPERTY_ROW_OPS: [FieldOp; 3] = [FieldOp::Square, FieldOp::SquareDirect, FieldOp::Sqrt];

/// The positive controls' parameters: a loop that branches on the operand
/// in every iteration, and a loop whose length is the operand. Both must
/// cross the threshold, or the run says nothing.
const BRANCH_CONTROL_ITERATIONS: u64 = 64;
/// The branch is taken when operand + iteration is a multiple of this.
const BRANCH_CONTROL_PERIOD: u64 = 7;
/// The taken arm's work, distinct from the other arm's increment.
const BRANCH_CONTROL_TAKEN_FACTOR: u64 = 3;
/// The branch control's fixed class: one byte value.
const BRANCH_CONTROL_FIXED_BYTE: u8 = 0;
/// The loop control's fixed class: the shortest loop, the extreme against
/// random odd lengths.
const LOOP_CONTROL_SHORTEST: u8 = 1;
/// Knuth's MMIX LCG multiplier: one iteration's work in the loop control.
const LOOP_CONTROL_MULTIPLIER: u64 = 6_364_136_223_846_793_005;

/// The canonical operands the two halves of a `HelioseleneField` square
/// see.
type HelioCanonical = Canonical<HelioseleneField>;

/// The word a wide (lo, hi) product contributes to the sink; both halves
/// reach the optimisation barrier, so neither can be dropped.
fn wide_sink_word(product: (U256, U256)) -> u64 {
    let (lo, _hi) = black_box(product);
    lo.as_limbs()[0].0
}

/// Every section, in output order.
pub fn run(h: &mut impl Bench) {
    let mut constants = Rng::from_os();

    h.section("null control (both classes fresh; must show no difference)");
    for field in FieldId::ALL {
        for op in NULL_ROW_OPS {
            field_row(h, field, Design::Null, op, &mut constants);
        }
    }

    for field in FieldId::ALL {
        h.section(field.heading());
        for op in FieldOp::ALL {
            for design in Design::TEST {
                field_row(h, field, design, op, &mut constants);
            }
        }
    }

    h.section("constant-value control (class 0: one value, allocated fresh per batch; class 1: fresh values)");
    for field in FieldId::ALL {
        for op in CONSTANT_ROW_OPS {
            field_row(h, field, Design::Constant, op, &mut constants);
        }
    }

    h.section("operand property (class 0: structured values, regenerated per batch; class 1: random) — which property moves the time?");
    for field in FieldId::ALL {
        for op in PROPERTY_ROW_OPS {
            for shape in Shape::ALL {
                field_row(h, field, Design::Shaped(shape), op, &mut constants);
            }
        }
    }

    h.section("the two halves of a square (crypto-bigint 0.5.5 U256::square_wide is shared by both fields; the reduction is not)");
    // Operands are canonical HelioseleneField values, the whole field
    // [0, p) as its arithmetic holds them.
    tested(h, "half: U256::square_wide", HelioCanonical::sample, |a| {
        wide_sink_word(a.value.square_wide())
    });
    tested(
        h,
        "half: U256::mul_wide",
        <(HelioCanonical, HelioCanonical)>::sample,
        |(a, b)| wide_sink_word(a.value.mul_wide(&b.value)),
    );
    // HelioseleneField::wide_reduce is the reduction of a 512-bit value
    // (red512) on its own, on uniform 512-bit input.
    tested(
        h,
        "half: helio wide_reduce (red512)",
        <[u8; 64]>::sample,
        |b| sink_word(&HelioseleneField::wide_reduce(*b)),
    );
    // The reduction fed with what a square produces.
    tested(
        h,
        "half: red512 of a square_wide",
        HelioCanonical::sample,
        |a| {
            let (lo, hi) = a.value.square_wide();
            let mut wide = [0u8; 64];
            wide[..32].copy_from_slice(&lo.to_le_bytes());
            wide[32..].copy_from_slice(&hi.to_le_bytes());
            sink_word(&HelioseleneField::wide_reduce(wide))
        },
    );

    h.section("crypto-bigint 0.5.5 Residue::pow with a secret exponent (BINSEC found a branch; unreached by our code)");
    tested(
        h,
        "residue pow (secret exponent)",
        <(Residue25519, U256)>::sample,
        |(a, e)| black_box(a.pow(e).retrieve()).as_limbs()[0].0,
    );

    h.section("positive controls (must show a class difference)");
    h.row(
        "control: branch on a byte",
        Contrast::Constant(BRANCH_CONTROL_FIXED_BYTE),
        u8::sample,
        |b| {
            let mut s = 0u64;
            for i in 0..BRANCH_CONTROL_ITERATIONS {
                if (u64::from(*b) + i).is_multiple_of(BRANCH_CONTROL_PERIOD) {
                    s = black_box(s.wrapping_mul(BRANCH_CONTROL_TAKEN_FACTOR))
                } else {
                    s = black_box(s + 1)
                }
            }
            s
        },
    );
    h.row(
        "control: data-dependent loop",
        Contrast::Constant(LOOP_CONTROL_SHORTEST),
        |rng: &mut Rng| u8::sample(rng) | LOOP_CONTROL_SHORTEST,
        |b| {
            let mut s = 0u64;
            for _ in 0..u64::from(*b) {
                s = black_box(s.wrapping_mul(LOOP_CONTROL_MULTIPLIER).wrapping_add(1))
            }
            s
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::path::Path;

    /// The bench that records row names without running anything.
    #[derive(Default)]
    struct Catalogue(Vec<String>);

    impl Bench for Catalogue {
        fn section(&mut self, _heading: &str) {}
        fn row<I: Clone, O: FnMut(&I) -> u64>(
            &mut self,
            name: &str,
            _contrast: Contrast<I>,
            _draw: impl Fn(&mut Rng) -> I,
            _op: O,
        ) {
            self.0.push(name.to_owned());
        }
    }

    fn catalogue() -> Vec<String> {
        let mut catalogue = Catalogue::default();
        run(&mut catalogue);
        catalogue.0
    }

    #[test]
    fn row_names_are_unique() {
        let rows = catalogue();
        let unique: HashSet<&String> = rows.iter().collect();
        assert_eq!(unique.len(), rows.len(), "duplicate row names");
    }

    /// Every test row has its equal-familiarity companion: a row that
    /// differs fixed-against-fresh is only a finding if the companion
    /// differs too.
    #[test]
    fn every_test_row_has_its_companion() {
        let rows: HashSet<String> = catalogue().into_iter().collect();
        let controls = ["null: ", "constant: ", "property: ", "control: "];
        for row in &rows {
            if controls.iter().any(|p| row.starts_with(p)) || row.ends_with(FIXED_PAIR_SUFFIX) {
                continue;
            }
            assert!(rows.contains(&companion(row)), "{row} has no companion");
        }
    }

    #[test]
    fn both_fields_get_the_same_rows() {
        let rows = catalogue();
        let on = |label: &str| -> HashSet<String> {
            rows.iter()
                .filter(|r| r.contains(&format!("{label} ")))
                .map(|r| r.replacen(&format!("{label} "), "<field> ", 1))
                .collect()
        };
        let mut helio = on(HelioseleneField::LABEL);
        // The halves are a decomposition of the HelioseleneField square.
        helio.retain(|r| !r.starts_with("half: "));
        assert_eq!(on(Field25519::LABEL), helio);
    }

    #[test]
    fn the_run_has_null_and_positive_controls() {
        let rows = catalogue();
        assert!(rows.iter().any(|r| r.starts_with("null: ")));
        assert_eq!(
            rows.iter().filter(|r| r.starts_with("control: ")).count(),
            2
        );
    }

    /// Row names the harness no longer has, each still cited by the record
    /// of the design step that retired it (`dynamic-x86_64-diagnostics.txt`,
    /// 2026-10-24). A retired name is never reused for another row.
    struct RetiredRow {
        name: &'static str,
        /// What the step showed and what took its place.
        disposition: &'static str,
    }

    const RETIRED_ROWS: [RetiredRow; 10] = {
        const FIRST_NULL: &str = "first design's null naming; now `null: <field> <operation>`";
        const REPEAT: &str = "one fresh value repeated through a batch runs faster whatever \
            the value: no value repeats inside a batch now, and the constant rows keep the \
            repeated value as a control";
        const ZERO: &str =
            "a zero fixed class; the constant and operand-property rows took its place";
        const PAIR: &str = "first fixed-pair naming; now `<row> [fixed-pair]`";
        [
            RetiredRow {
                name: "null: fe25519 mul random/random",
                disposition: FIRST_NULL,
            },
            RetiredRow {
                name: "null: helio mul random/random",
                disposition: FIRST_NULL,
            },
            RetiredRow {
                name: "repeat-null: fe25519 square",
                disposition: REPEAT,
            },
            RetiredRow {
                name: "repeat-null: helio mul",
                disposition: REPEAT,
            },
            RetiredRow {
                name: "repeat-null: helio square",
                disposition: REPEAT,
            },
            RetiredRow {
                name: "zero-fixed: fe25519 square",
                disposition: ZERO,
            },
            RetiredRow {
                name: "zero-fixed: helio square",
                disposition: ZERO,
            },
            RetiredRow {
                name: "fixed-pair: fe25519 square",
                disposition: PAIR,
            },
            RetiredRow {
                name: "fixed-pair: helio mul",
                disposition: PAIR,
            },
            RetiredRow {
                name: "fixed-pair: helio square",
                disposition: PAIR,
            },
        ]
    };

    #[test]
    fn a_retired_name_is_not_reused() {
        let rows: HashSet<String> = catalogue().into_iter().collect();
        for retired in &RETIRED_ROWS {
            assert!(!retired.disposition.is_empty());
            assert!(!rows.contains(retired.name), "{} is retired", retired.name);
        }
    }

    /// The name each line of a committed dynamic record cites.
    fn recorded_rows(record: &str) -> impl Iterator<Item = &str> {
        record.lines().filter_map(|line| {
            let end = line
                .find(" t=")
                .or_else(|| line.find(" only one class run"))?;
            Some(line[..end].trim_end())
        })
    }

    #[test]
    fn every_recorded_row_name_still_exists() {
        let rows: HashSet<String> = catalogue().into_iter().collect();
        let results = Path::new(env!("CARGO_MANIFEST_DIR")).join("../results");
        let mut checked = 0;
        let days = std::fs::read_dir(&results)
            .unwrap()
            .map(|e| e.unwrap().path());
        for day in days.filter(|path| path.is_dir()) {
            for record in std::fs::read_dir(day).unwrap() {
                let path = record.unwrap().path();
                let file = path.file_name().unwrap().to_string_lossy();
                if !file.starts_with("dynamic-") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                for row in recorded_rows(&text) {
                    let retired = RETIRED_ROWS.iter().any(|r| r.name == row);
                    assert!(
                        rows.contains(row) || retired,
                        "{file} cites {row:?}: neither a row nor a retired row"
                    );
                    checked += 1;
                }
            }
        }
        // The check must have a subject (rule 47): records exist and cite rows.
        assert!(
            checked > 0,
            "no dynamic record rows found under {results:?}"
        );
    }
}
