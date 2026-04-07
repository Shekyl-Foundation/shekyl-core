use ciphersuite::Ciphersuite;

use ec_divisors::DivisorCurve;
use generalized_bulletproofs::Generators;

use crate::*;

/// The parameters for full-chain membership proofs.
#[derive(Clone, Debug)]
pub struct FcmpParams<C: FcmpCurves>
where
  <C::OC as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
  <C::C1 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C2 as Ciphersuite>::F>,
  <C::C2 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
{
  /// Generators for the first curve.
  pub(crate) curve_1_generators: Generators<C::C1>,
  /// Generators for the second curve.
  pub(crate) curve_2_generators: Generators<C::C2>,

  /// Initialization point for the hash function over the first curve.
  pub(crate) curve_1_hash_init: <C::C1 as Ciphersuite>::G,
  /// Initialization point for the hash function over the first curve.
  pub(crate) curve_2_hash_init: <C::C2 as Ciphersuite>::G,

  pub(crate) G_table: GeneratorTable<<C::C1 as Ciphersuite>::F, C::OcParameters>,
  pub(crate) T_table: GeneratorTable<<C::C1 as Ciphersuite>::F, C::OcParameters>,
  pub(crate) U_table: GeneratorTable<<C::C1 as Ciphersuite>::F, C::OcParameters>,
  pub(crate) V_table: GeneratorTable<<C::C1 as Ciphersuite>::F, C::OcParameters>,
  pub(crate) H_1_table: GeneratorTable<<C::C2 as Ciphersuite>::F, C::C1Parameters>,
  pub(crate) H_2_table: GeneratorTable<<C::C1 as Ciphersuite>::F, C::C2Parameters>,
}

impl<C: FcmpCurves> FcmpParams<C>
where
  <C::OC as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
  <C::C1 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C2 as Ciphersuite>::F>,
  <C::C2 as Ciphersuite>::G: DivisorCurve<FieldElement = <C::C1 as Ciphersuite>::F>,
{
  /// Create a new set of parameters.
  ///
  /// Returns `None` if any generator point is the identity (and therefore has no affine
  /// coordinates).
  #[allow(clippy::too_many_arguments)]
  pub fn new(
    curve_1_generators: Generators<C::C1>,
    curve_2_generators: Generators<C::C2>,
    curve_1_hash_init: <C::C1 as Ciphersuite>::G,
    curve_2_hash_init: <C::C2 as Ciphersuite>::G,
    G: <<C as FcmpCurves>::OC as Ciphersuite>::G,
    T: <<C as FcmpCurves>::OC as Ciphersuite>::G,
    U: <<C as FcmpCurves>::OC as Ciphersuite>::G,
    V: <<C as FcmpCurves>::OC as Ciphersuite>::G,
  ) -> Option<Self> {
    let oc_curve_spec =
      CurveSpec { a: <<C::OC as Ciphersuite>::G>::a(), b: <<C::OC as Ciphersuite>::G>::b() };
    let (g_x, g_y) = <<C as FcmpCurves>::OC as Ciphersuite>::G::to_xy(G)?;
    let G_table = GeneratorTable::new(&oc_curve_spec, g_x, g_y);
    let (t_x, t_y) = <<C as FcmpCurves>::OC as Ciphersuite>::G::to_xy(T)?;
    let T_table = GeneratorTable::new(&oc_curve_spec, t_x, t_y);
    let (u_x, u_y) = <<C as FcmpCurves>::OC as Ciphersuite>::G::to_xy(U)?;
    let U_table = GeneratorTable::new(&oc_curve_spec, u_x, u_y);
    let (v_x, v_y) = <<C as FcmpCurves>::OC as Ciphersuite>::G::to_xy(V)?;
    let V_table = GeneratorTable::new(&oc_curve_spec, v_x, v_y);

    let c1_curve_spec =
      CurveSpec { a: <<C::C1 as Ciphersuite>::G>::a(), b: <<C::C1 as Ciphersuite>::G>::b() };
    let (h_1_x, h_1_y) =
      <<C as FcmpCurves>::C1 as Ciphersuite>::G::to_xy(curve_1_generators.h())?;
    let H_1_table = GeneratorTable::new(&c1_curve_spec, h_1_x, h_1_y);

    let c2_curve_spec =
      CurveSpec { a: <<C::C2 as Ciphersuite>::G>::a(), b: <<C::C2 as Ciphersuite>::G>::b() };
    let (h_2_x, h_2_y) =
      <<C as FcmpCurves>::C2 as Ciphersuite>::G::to_xy(curve_2_generators.h())?;
    let H_2_table = GeneratorTable::new(&c2_curve_spec, h_2_x, h_2_y);

    Some(Self {
      curve_1_generators,
      curve_2_generators,
      curve_1_hash_init,
      curve_2_hash_init,
      G_table,
      T_table,
      U_table,
      V_table,
      H_1_table,
      H_2_table,
    })
  }
}
