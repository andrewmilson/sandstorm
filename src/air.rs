use gpu_poly::GpuVec;
use layouts::layout6;
use ministark::air::AirConfig;
use ministark::challenges::Challenges;
use ministark::constraints::CompositionConstraint;
use ministark::constraints::Constraint;
use ministark::hints::Hints;
use ministark::utils::FieldVariant;
use ministark::Matrix;

// include!(concat!(env!("OUT_DIR"), "/layout6.rs"));

pub struct Layout6Config;

impl AirConfig for Layout6Config {
    const NUM_BASE_COLUMNS: usize = layout6::AirConfig::NUM_BASE_COLUMNS;
    const NUM_EXTENSION_COLUMNS: usize = layout6::AirConfig::NUM_EXTENSION_COLUMNS;
    type Fp = <layout6::AirConfig as AirConfig>::Fp;
    type Fq = <layout6::AirConfig as AirConfig>::Fq;
    type PublicInputs = <layout6::AirConfig as AirConfig>::PublicInputs;

    fn constraints(trace_len: usize) -> Vec<Constraint<FieldVariant<Self::Fp, Self::Fq>>> {
        layout6::AirConfig::constraints(trace_len)
    }

    fn gen_hints(
        trace_len: usize,
        public_input: &Self::PublicInputs,
        challenges: &Challenges<Self::Fq>,
    ) -> Hints<Self::Fq> {
        layout6::AirConfig::gen_hints(trace_len, public_input, challenges)
    }

    // fn eval_constraint(
    //     _composition_constraint: &CompositionConstraint<FieldVariant<Self::Fp,
    // Self::Fq>>,     challenges: &Challenges<Self::Fq>,
    //     hints: &[Self::Fq],
    //     composition_constraint_coeffs: &[Self::Fq],
    //     lde_step: usize,
    //     x_lde: GpuVec<Self::Fp>,
    //     base_trace_lde: &Matrix<Self::Fp>,
    //     extension_trace_lde: Option<&Matrix<Self::Fq>>,
    // ) -> Matrix<Self::Fq> {
    //     eval::<Self>(
    //         challenges,
    //         hints,
    //         composition_constraint_coeffs,
    //         lde_step,
    //         x_lde,
    //         base_trace_lde,
    //         extension_trace_lde,
    //     )
    // }
}
