#![feature(async_fn_in_trait, allocator_api)]

use ark_ff::PrimeField;
use ark_poly::domain::EvaluationDomain;
use layouts::CairoAirConfig;
use layouts::CairoAuxInput;
use layouts::CairoExecutionTrace;
use ministark::channel::ProverChannel;
use ministark::composer::DeepPolyComposer;
use ministark::fri::FriProver;
use ministark::prover::ProvingError;
use ministark::trace::Queries;
use ministark::utils::GpuAllocator;
use ministark::utils::GpuVec;
use ministark::Air;
use ministark::Matrix;
use ministark::Proof;
use ministark::ProofOptions;
use ministark::Prover;
use ruint::aliases::U256;
use ruint::uint;
use sha2::Sha256;
use std::marker::PhantomData;
use std::time::Instant;

#[derive(Default)]
pub struct CairoAuxInputLayout6 {
    pub log_n_steps: U256,
    pub rc_min: U256,
    pub rc_max: U256,
    pub layout_code: U256,
    pub program_begin_addr: U256,
    pub program_stop_ptr: U256,
    pub execution_begin_addr: U256,
    pub execution_stop_ptr: U256,
    pub output_begin_addr: U256,
    pub output_stop_ptr: U256,
    pub pedersen_begin_addr: U256,
    pub pedersen_stop_ptr: U256,
    pub range_check_begin_addr: U256,
    pub range_check_stop_ptr: U256,
    pub ecdsa_begin_addr: U256,
    pub ecdsa_stop_ptr: U256,
    pub bitwise_begin_addr: U256,
    pub bitwise_stop_addr: U256,
    pub ec_op_begin_addr: U256,
    pub ec_op_stop_addr: U256,
    pub poseidon_begin_addr: U256,
    pub poseidon_stop_ptr: U256,
    pub public_memory_padding_addr: U256,
    pub public_memory_padding_value: U256,
    pub n_public_memory_pages: U256,
    pub public_memory: U256,
}

impl CairoAuxInputLayout6 {
    pub const OFFSET_LOG_N_STEPS: usize = 0;
    pub const OFFSET_RC_MIN: usize = 1;
    pub const OFFSET_RC_MAX: usize = 2;
    pub const OFFSET_LAYOUT_CODE: usize = 3;
    pub const OFFSET_PROGRAM_BEGIN_ADDR: usize = 4;
    pub const OFFSET_PROGRAM_STOP_PTR: usize = 5;
    pub const OFFSET_EXECUTION_BEGIN_ADDR: usize = 6;
    pub const OFFSET_EXECUTION_STOP_PTR: usize = 7;
    pub const OFFSET_OUTPUT_BEGIN_ADDR: usize = 8;
    pub const OFFSET_OUTPUT_STOP_PTR: usize = 9;
    pub const OFFSET_PEDERSEN_BEGIN_ADDR: usize = 10;
    pub const OFFSET_PEDERSEN_STOP_PTR: usize = 11;
    pub const OFFSET_RANGE_CHECK_BEGIN_ADDR: usize = 12;
    pub const OFFSET_RANGE_CHECK_STOP_PTR: usize = 13;
    pub const OFFSET_ECDSA_BEGIN_ADDR: usize = 14;
    pub const OFFSET_ECDSA_STOP_PTR: usize = 15;
    pub const OFFSET_BITWISE_BEGIN_ADDR: usize = 16;
    pub const OFFSET_BITWISE_STOP_ADDR: usize = 17;
    pub const OFFSET_EC_OP_BEGIN_ADDR: usize = 18;
    pub const OFFSET_EC_OP_STOP_ADDR: usize = 19;
    pub const OFFSET_POSEIDON_BEGIN_ADDR: usize = 20;
    pub const OFFSET_POSEIDON_STOP_PTR: usize = 21;
    pub const OFFSET_PUBLIC_MEMORY_PADDING_ADDR: usize = 22;
    pub const OFFSET_PUBLIC_MEMORY_PADDING_VALUE: usize = 23;
    pub const OFFSET_N_PUBLIC_MEMORY_PAGES: usize = 24;
    pub const OFFSET_PUBLIC_MEMORY: usize = 25;
}

/// Generate a proof just like StarkWare's SHARP (SHARed Prover)
pub struct StarkWareProver<A: CairoAirConfig, T: CairoExecutionTrace> {
    options: ProofOptions,
    _marker: PhantomData<(A, T)>,
}

impl<A: CairoAirConfig, T: CairoExecutionTrace<Fp = A::Fp, Fq = A::Fq>> Prover
    for StarkWareProver<A, T>
where
    A::Fp: PrimeField,
{
    type Fp = A::Fp;
    type Fq = A::Fq;
    type AirConfig = A;
    type Trace = T;

    fn new(options: ProofOptions) -> Self {
        StarkWareProver {
            options,
            _marker: PhantomData,
        }
    }

    fn options(&self) -> ProofOptions {
        self.options
    }

    fn get_pub_inputs(&self, trace: &Self::Trace) -> CairoAuxInput<A::Fp> {
        trace.auxiliary_input()
    }

    async fn generate_proof(
        &self,
        trace: Self::Trace,
    ) -> Result<Proof<Self::AirConfig>, ProvingError> {
        println!("YEEEE!!!");

        let now = Instant::now();
        let options = self.options();
        let trace_info = trace.info();
        let execution_info = self.get_pub_inputs(&trace);
        let air = Air::new(trace_info.trace_len, execution_info, options);
        let mut channel = ProverChannel::<Self::AirConfig, Sha256>::new(&air);

        let now = Instant::now();
        let trace_xs = air.trace_domain();
        let lde_xs = air.lde_domain();
        let base_trace = trace.base_columns();
        let base_trace_polys = base_trace.interpolate(trace_xs);
        assert_eq!(Self::Trace::NUM_BASE_COLUMNS, base_trace_polys.num_cols());
        let base_trace_lde = base_trace_polys.evaluate(lde_xs);
        let base_trace_lde_tree = base_trace_lde.commit_to_rows::<Sha256>();
        channel.commit_base_trace(base_trace_lde_tree.root());
        let challenges = air.gen_challenges(&mut channel.public_coin);
        let hints = air.gen_hints(&challenges);
        println!("Base trace: {:?}", now.elapsed());

        let now = Instant::now();
        let extension_trace = trace.build_extension_columns(&challenges);
        let num_extension_columns = extension_trace.as_ref().map_or(0, Matrix::num_cols);
        assert_eq!(Self::Trace::NUM_EXTENSION_COLUMNS, num_extension_columns);
        let extension_trace_polys = extension_trace.as_ref().map(|t| t.interpolate(trace_xs));
        let extension_trace_lde = extension_trace_polys.as_ref().map(|p| p.evaluate(lde_xs));
        let extension_trace_tree = extension_trace_lde.as_ref().map(Matrix::commit_to_rows);
        if let Some(t) = extension_trace_tree.as_ref() {
            channel.commit_extension_trace(t.root());
        }
        println!("Extension trace: {:?}", now.elapsed());

        // #[cfg(all(feature = "std", debug_assertions))]
        // air.validate_constraints(&challenges, &hints, base_trace,
        // extension_trace.as_ref());
        drop((base_trace, extension_trace));

        let now = Instant::now();
        let composition_constraint_coeffs =
            air.gen_composition_constraint_coeffs(&mut channel.public_coin);
        let x_lde = lde_xs.elements().collect::<Vec<_>>();
        println!("X lde: {:?}", now.elapsed());
        let now = Instant::now();
        let composition_evals = Self::AirConfig::eval_constraint(
            air.composition_constraint(),
            &challenges,
            &hints,
            &composition_constraint_coeffs,
            air.lde_blowup_factor(),
            x_lde.to_vec_in(GpuAllocator),
            &base_trace_lde,
            extension_trace_lde.as_ref(),
        );
        println!("Constraint eval: {:?}", now.elapsed());
        let now = Instant::now();
        let composition_poly = composition_evals.into_polynomials(air.lde_domain());
        let composition_trace_cols = air.ce_blowup_factor();
        let composition_trace_polys = Matrix::from_rows(
            GpuVec::try_from(composition_poly)
                .unwrap()
                .chunks(composition_trace_cols)
                .map(<[Self::Fq]>::to_vec)
                .collect(),
        );
        let composition_trace_lde = composition_trace_polys.evaluate(air.lde_domain());
        let composition_trace_lde_tree = composition_trace_lde.commit_to_rows();
        channel.commit_composition_trace(composition_trace_lde_tree.root());
        println!("Constraint composition polys: {:?}", now.elapsed());

        let now = Instant::now();
        let mut deep_poly_composer = DeepPolyComposer::new(
            &air,
            channel.get_ood_point(),
            &base_trace_polys,
            extension_trace_polys.as_ref(),
            composition_trace_polys,
        );
        let (execution_trace_oods, composition_trace_oods) = deep_poly_composer.get_ood_evals();
        channel.send_execution_trace_ood_evals(execution_trace_oods);
        channel.send_composition_trace_ood_evals(composition_trace_oods);
        let deep_coeffs = air.gen_deep_composition_coeffs(&mut channel.public_coin);
        let deep_composition_poly = deep_poly_composer.into_deep_poly(deep_coeffs);
        let deep_composition_lde = deep_composition_poly.into_evaluations(lde_xs);
        println!("Deep composition: {:?}", now.elapsed());

        let now = Instant::now();
        let mut fri_prover = FriProver::<Self::Fq, Sha256>::new(air.options().into_fri_options());
        fri_prover.build_layers(&mut channel, deep_composition_lde.try_into().unwrap());

        channel.grind_fri_commitments();

        let query_positions = channel.get_fri_query_positions();
        let fri_proof = fri_prover.into_proof(&query_positions);
        println!("FRI: {:?}", now.elapsed());

        let queries = Queries::new(
            &base_trace_lde,
            extension_trace_lde.as_ref(),
            &composition_trace_lde,
            &base_trace_lde_tree,
            extension_trace_tree.as_ref(),
            &composition_trace_lde_tree,
            &query_positions,
        );
        Ok(channel.build_proof(queries, fri_proof))
    }
}
