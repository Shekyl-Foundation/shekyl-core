//! Unit, adversarial-parse, and property tests for [`AtomicUnits`].

use super::*;
use proptest::prelude::*;

// ---- denomination constants -------------------------------------------------

#[test]
fn denomination_is_ten_to_the_nine() {
    assert_eq!(ATOMIC_UNITS_PER_SKL, 1_000_000_000);
    assert_eq!(DISPLAY_DECIMAL_POINT, 9);
    // The same relationship the build-time and `const _` guards assert.
    assert_eq!(
        ATOMIC_UNITS_PER_SKL,
        10u64.pow(u32::from(DISPLAY_DECIMAL_POINT))
    );
}

// ---- checked arithmetic -----------------------------------------------------

#[test]
fn checked_add_basic_and_overflow() {
    let a = AtomicUnits::from_raw(10);
    let b = AtomicUnits::from_raw(32);
    assert_eq!(a.checked_add(b), Some(AtomicUnits::from_raw(42)));

    let max = AtomicUnits::from_raw(u64::MAX);
    let one = AtomicUnits::from_raw(1);
    assert_eq!(max.checked_add(one), None);
}

#[test]
fn checked_sub_basic_and_underflow() {
    let a = AtomicUnits::from_raw(42);
    let b = AtomicUnits::from_raw(10);
    assert_eq!(a.checked_sub(b), Some(AtomicUnits::from_raw(32)));
    assert_eq!(b.checked_sub(a), None);
    assert_eq!(a.checked_sub(a), Some(AtomicUnits::ZERO));
}

#[test]
fn checked_sum_basic_empty_and_overflow() {
    let xs = [
        AtomicUnits::from_raw(1),
        AtomicUnits::from_raw(2),
        AtomicUnits::from_raw(3),
    ];
    assert_eq!(AtomicUnits::checked_sum(xs), Some(AtomicUnits::from_raw(6)));

    let empty: [AtomicUnits; 0] = [];
    assert_eq!(AtomicUnits::checked_sum(empty), Some(AtomicUnits::ZERO));

    let overflow = [AtomicUnits::from_raw(u64::MAX), AtomicUnits::from_raw(1)];
    assert_eq!(AtomicUnits::checked_sum(overflow), None);
}

#[test]
fn zero_and_is_zero() {
    assert!(AtomicUnits::ZERO.is_zero());
    assert!(!AtomicUnits::from_raw(1).is_zero());
    assert_eq!(AtomicUnits::default(), AtomicUnits::ZERO);
}

#[test]
fn ord_is_natural_u64_order() {
    assert!(AtomicUnits::from_raw(1) < AtomicUnits::from_raw(2));
    assert!(AtomicUnits::ZERO < AtomicUnits::from_raw(u64::MAX));
    assert_eq!(AtomicUnits::from_raw(7), AtomicUnits::from_raw(7));
}

// ---- raw boundary -----------------------------------------------------------

#[test]
fn from_raw_to_raw_round_trip() {
    for v in [0u64, 1, 1_000_000_000, u64::MAX] {
        assert_eq!(AtomicUnits::from_raw(v).to_raw(), v);
    }
}

// ---- display / debug carry the unit marker, never SKL -----------------------

#[test]
fn display_and_debug_render_atomic_units_with_marker() {
    let a = AtomicUnits::from_raw(12_345);
    assert_eq!(format!("{a}"), "12345 au");
    assert_eq!(format!("{a:?}"), "AtomicUnits(12345 au)");
}

// ---- SKL string formatting --------------------------------------------------

#[test]
fn to_skl_string_fixed_width() {
    assert_eq!(AtomicUnits::ZERO.to_skl_string(), "0.000000000");
    assert_eq!(AtomicUnits::from_raw(1).to_skl_string(), "0.000000001");
    assert_eq!(
        AtomicUnits::from_raw(1_000_000_000).to_skl_string(),
        "1.000000000"
    );
    assert_eq!(
        AtomicUnits::from_raw(12_345_000_000).to_skl_string(),
        "12.345000000"
    );
    // Max supply in atomic units (2^32 whole SKL).
    assert_eq!(
        AtomicUnits::from_raw(4_294_967_296_000_000_000).to_skl_string(),
        "4294967296.000000000"
    );
}

#[test]
fn from_skl_str_valid() {
    assert_eq!(AtomicUnits::from_skl_str("0").unwrap(), AtomicUnits::ZERO);
    assert_eq!(
        AtomicUnits::from_skl_str("0.000000001").unwrap(),
        AtomicUnits::from_raw(1)
    );
    assert_eq!(
        AtomicUnits::from_skl_str("1").unwrap(),
        AtomicUnits::from_raw(1_000_000_000)
    );
    assert_eq!(
        AtomicUnits::from_skl_str("12.345").unwrap(),
        AtomicUnits::from_raw(12_345_000_000)
    );
    // Trailing zeros and full-width fraction both parse.
    assert_eq!(
        AtomicUnits::from_skl_str("12.345000000").unwrap(),
        AtomicUnits::from_raw(12_345_000_000)
    );
    // Leading zeros in the integer part are accepted.
    assert_eq!(
        AtomicUnits::from_skl_str("007").unwrap(),
        AtomicUnits::from_raw(7_000_000_000)
    );
}

// ---- adversarial parse (the money-input path) -------------------------------

#[test]
fn from_skl_str_rejects_too_many_decimals_not_truncate() {
    // 10 fractional digits > DISPLAY_DECIMAL_POINT(9): reject, never truncate.
    assert_eq!(
        AtomicUnits::from_skl_str("0.0000000001"),
        Err(ParseAmountError::TooManyDecimals)
    );
}

#[test]
fn from_skl_str_rejects_overflow() {
    // u64::MAX is ~1.84e19 atomic; 18_446_744_074 SKL * 10^9 overflows.
    assert_eq!(
        AtomicUnits::from_skl_str("18446744074"),
        Err(ParseAmountError::Overflow)
    );
    assert_eq!(
        AtomicUnits::from_skl_str("99999999999999999999"),
        Err(ParseAmountError::Overflow)
    );
}

#[test]
fn from_skl_str_rejects_malformed() {
    assert_eq!(AtomicUnits::from_skl_str(""), Err(ParseAmountError::Empty));
    assert_eq!(
        AtomicUnits::from_skl_str("."),
        Err(ParseAmountError::Malformed)
    );
    assert_eq!(
        AtomicUnits::from_skl_str(".5"),
        Err(ParseAmountError::Malformed)
    );
    assert_eq!(
        AtomicUnits::from_skl_str("-1"),
        Err(ParseAmountError::Malformed)
    );
    assert_eq!(
        AtomicUnits::from_skl_str("+1"),
        Err(ParseAmountError::Malformed)
    );
    assert_eq!(
        AtomicUnits::from_skl_str("1.2.3"),
        Err(ParseAmountError::MultipleDots)
    );
    assert_eq!(
        AtomicUnits::from_skl_str("1.2x"),
        Err(ParseAmountError::Malformed)
    );
    assert_eq!(
        AtomicUnits::from_skl_str(" 1"),
        Err(ParseAmountError::Malformed)
    );
    assert_eq!(
        AtomicUnits::from_skl_str("1 "),
        Err(ParseAmountError::Malformed)
    );
    assert_eq!(
        AtomicUnits::from_skl_str("0x10"),
        Err(ParseAmountError::Malformed)
    );
}

// ---- serde transparency: JSON number + postcard byte-identity vs u64 --------

#[test]
fn serde_json_is_a_bare_number() {
    let a = AtomicUnits::from_raw(123_456_789);
    let s = serde_json::to_string(&a).unwrap();
    assert_eq!(s, "123456789");
    let back: AtomicUnits = serde_json::from_str(&s).unwrap();
    assert_eq!(a, back);
    // Identical to the inner u64's JSON.
    assert_eq!(s, serde_json::to_string(&123_456_789u64).unwrap());
}

#[test]
fn postcard_is_byte_identical_to_u64() {
    for v in [0u64, 1, 127, 128, 1_000_000_000, u64::MAX] {
        let typed = postcard::to_allocvec(&AtomicUnits::from_raw(v)).unwrap();
        let raw = postcard::to_allocvec(&v).unwrap();
        assert_eq!(typed, raw, "postcard bytes differ for {v}");
        let back: AtomicUnits = postcard::from_bytes(&typed).unwrap();
        assert_eq!(back, AtomicUnits::from_raw(v));
    }
}

// ---- zeroize wipes ----------------------------------------------------------

#[test]
fn zeroize_wipes_to_zero() {
    let mut a = AtomicUnits::from_raw(0xDEAD_BEEF);
    a.zeroize();
    assert_eq!(a, AtomicUnits::ZERO);
    assert_eq!(a.to_raw(), 0);
}

// ---- property tests (widest-blast-radius crate) -----------------------------

proptest! {
    #[test]
    fn prop_from_raw_to_raw_total(v in any::<u64>()) {
        prop_assert_eq!(AtomicUnits::from_raw(v).to_raw(), v);
    }

    #[test]
    fn prop_skl_string_round_trip_total(v in any::<u64>()) {
        let a = AtomicUnits::from_raw(v);
        let s = a.to_skl_string();
        let back = AtomicUnits::from_skl_str(&s)
            .expect("to_skl_string output must parse back");
        prop_assert_eq!(a, back);
    }

    #[test]
    fn prop_checked_sum_equals_fold(xs in proptest::collection::vec(any::<u64>(), 0..32)) {
        let units: Vec<AtomicUnits> = xs.iter().copied().map(AtomicUnits::from_raw).collect();
        let summed = AtomicUnits::checked_sum(units.iter().copied());
        let folded = units.iter().copied().try_fold(AtomicUnits::ZERO, AtomicUnits::checked_add);
        prop_assert_eq!(summed, folded);
    }

    #[test]
    fn prop_checked_sub_inverts_checked_add(a in any::<u64>(), b in any::<u64>()) {
        let x = AtomicUnits::from_raw(a);
        let y = AtomicUnits::from_raw(b);
        if let Some(sum) = x.checked_add(y) {
            // (x + y) - y == x and (x + y) - x == y
            prop_assert_eq!(sum.checked_sub(y), Some(x));
            prop_assert_eq!(sum.checked_sub(x), Some(y));
        }
    }

    #[test]
    fn prop_serde_json_matches_inner_u64(v in any::<u64>()) {
        let typed = serde_json::to_string(&AtomicUnits::from_raw(v)).unwrap();
        let raw = serde_json::to_string(&v).unwrap();
        prop_assert_eq!(typed, raw);
    }

    #[test]
    fn prop_from_skl_str_never_panics(s in ".*") {
        // Must return cleanly (never panic) on arbitrary input; and whatever
        // parses must re-serialize and re-parse to the same value.
        if let Ok(parsed) = AtomicUnits::from_skl_str(&s) {
            prop_assert_eq!(AtomicUnits::from_skl_str(&parsed.to_skl_string()), Ok(parsed));
        }
    }
}

// ---- NonZeroAtomicUnits -----------------------------------------------------

#[test]
fn non_zero_atomic_units_rejects_zero_and_round_trips() {
    // Zero is unrepresentable — `new` returns `None`.
    assert!(NonZeroAtomicUnits::new(AtomicUnits::ZERO).is_none());
    assert!(NonZeroAtomicUnits::new(AtomicUnits::from_raw(0)).is_none());

    // A non-zero amount wraps and `get()` hands back the same `AtomicUnits`
    // (the money type is preserved, not dropped to a bare integer).
    let amount = AtomicUnits::from_raw(750_000_000);
    let nz = NonZeroAtomicUnits::new(amount).expect("non-zero");
    assert_eq!(nz.get(), amount);
    assert_eq!(nz.get().to_raw(), 750_000_000);
}
