/// Combine `lhs` elementwise with `rhs`, in place.
///
/// The two slices must be the same length. A mismatch is a fault in this crate's own algebra: a
/// `zip` would silently drop the longer slice's tail and compute a wrong result, so it is refused
/// in every build, with `operation` naming what was attempted.
pub(crate) fn zip_exact<L, R>(
    lhs: &mut [L],
    rhs: &[R],
    operation: &'static str,
    mut combine: impl FnMut(&mut L, &R),
) {
    assert_eq!(
        lhs.len(),
        rhs.len(),
        "{operation} of vectors of different lengths"
    );
    for (l, r) in lhs.iter_mut().zip(rhs) {
        combine(l, r);
    }
}
