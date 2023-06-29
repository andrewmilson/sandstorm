use crate::air::AirConfig;
use crate::challenges::Challenges;
use crate::composer::DeepCompositionCoeffs;
use crate::constraints::AlgebraicItem;
use crate::constraints::CompositionItem;
use crate::fri;
use crate::fri::FriVerifier;
use crate::hints::Hints;
use crate::merkle;
use crate::merkle::MerkleTree;
use crate::random::PublicCoin;
use crate::utils::FieldVariant;
use crate::Air;
// use crate::channel::VerifierChannel;
use crate::Proof;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use ark_ff::Field;
use ark_ff::One;
use ark_ff::Zero;
use ark_poly::EvaluationDomain;
use ark_serialize::CanonicalSerialize;
use digest::Digest;
use digest::Output;
use layouts::CairoAirConfig;
use ministark::fri::VerificationError;
use ministark::Proof;
use rand::Rng;
use sha2::Sha256;

#[allow(clippy::too_many_lines)]
pub fn verify<A: CairoAirConfig>(proof: Proof<A>) -> Result<(), VerificationError> {
    use VerificationError::*;

    let Self {
        base_trace_commitment,
        extension_trace_commitment,
        composition_trace_commitment,
        execution_trace_ood_evals,
        composition_trace_ood_evals,
        trace_queries,
        trace_len,
        public_inputs,
        options,
        fri_proof,
        pow_nonce,
        ..
    } = self;

    let mut seed = Vec::new();
    public_inputs.serialize_compressed(&mut seed).unwrap();
    trace_len.serialize_compressed(&mut seed).unwrap();
    options.serialize_compressed(&mut seed).unwrap();
    let mut public_coin = PublicCoin::<Sha256>::new(&seed);

    let air = Air::new(trace_len, public_inputs, options);

    let base_trace_commitment = Output::<Sha256>::from_iter(base_trace_commitment);
    public_coin.reseed(&&*base_trace_commitment);
    let challenges = air.gen_challenges(&mut public_coin);
    let hints = air.gen_hints(&challenges);

    let extension_trace_commitment = extension_trace_commitment.map(|extension_trace_commitment| {
        let extension_trace_commitment = Output::<Sha256>::from_iter(extension_trace_commitment);
        public_coin.reseed(&&*extension_trace_commitment);
        extension_trace_commitment
    });

    let composition_coeffs = air.gen_composition_constraint_coeffs(&mut public_coin);
    let composition_trace_commitment = Output::<Sha256>::from_iter(composition_trace_commitment);
    public_coin.reseed(&&*composition_trace_commitment);

    let z = public_coin.draw::<A::Fq>();
    public_coin.reseed(&execution_trace_ood_evals);
    // execution trace ood evaluation map
    let trace_ood_eval_map = air
        .trace_arguments()
        .into_iter()
        .zip(execution_trace_ood_evals)
        .collect::<BTreeMap<(usize, isize), A::Fq>>();
    let calculated_ood_constraint_evaluation = ood_constraint_evaluation::<A>(
        &composition_coeffs,
        &challenges,
        &hints,
        &trace_ood_eval_map,
        &air,
        z,
    );

    public_coin.reseed(&composition_trace_ood_evals);
    let mut acc = A::Fq::one();
    let provided_ood_constraint_evaluation =
        composition_trace_ood_evals
            .iter()
            .fold(A::Fq::zero(), |mut res, value| {
                res += *value * acc;
                acc *= z;
                res
            });

    if calculated_ood_constraint_evaluation != provided_ood_constraint_evaluation {
        return Err(InconsistentOodConstraintEvaluations);
    }

    let deep_coeffs = air.gen_deep_composition_coeffs(&mut public_coin);
    let fri_verifier = FriVerifier::<A::Fq, Sha256>::new(
        &mut public_coin,
        options.into_fri_options(),
        fri_proof,
        air.trace_len() - 1,
    )?;

    if options.grinding_factor != 0 {
        public_coin.reseed(&pow_nonce);
        if public_coin.seed_leading_zeros() < u32::from(options.grinding_factor) {
            return Err(FriProofOfWork);
        }
    }

    let mut rng = public_coin.draw_rng();
    let lde_domain_size = air.trace_len() * air.lde_blowup_factor();
    let query_positions = (0..options.num_queries)
        .map(|_| rng.gen_range(0..lde_domain_size))
        .collect::<Vec<usize>>();

    let base_trace_rows = trace_queries
        .base_trace_values
        .chunks(A::NUM_BASE_COLUMNS)
        .collect::<Vec<&[A::Fp]>>();
    let extension_trace_rows = if A::NUM_EXTENSION_COLUMNS > 0 {
        trace_queries
            .extension_trace_values
            .chunks(A::NUM_EXTENSION_COLUMNS)
            .collect::<Vec<&[A::Fq]>>()
    } else {
        Vec::new()
    };

    let composition_trace_rows = trace_queries
        .composition_trace_values
        .chunks(air.ce_blowup_factor())
        .collect::<Vec<&[A::Fq]>>();

    // base trace positions
    verify_positions::<Sha256>(
        &base_trace_commitment,
        &query_positions,
        &base_trace_rows,
        trace_queries.base_trace_proofs,
    )
    .map_err(|_| BaseTraceQueryDoesNotMatchCommitment)?;

    if let Some(extension_trace_commitment) = extension_trace_commitment {
        // extension trace positions
        verify_positions::<Sha256>(
            &extension_trace_commitment,
            &query_positions,
            &extension_trace_rows,
            trace_queries.extension_trace_proofs,
        )
        .map_err(|_| ExtensionTraceQueryDoesNotMatchCommitment)?;
    }

    // composition trace positions
    verify_positions::<Sha256>(
        &composition_trace_commitment,
        &query_positions,
        &composition_trace_rows,
        trace_queries.composition_trace_proofs,
    )
    .map_err(|_| CompositionTraceQueryDoesNotMatchCommitment)?;

    let deep_evaluations = deep_composition_evaluations(
        &air,
        &query_positions,
        &deep_coeffs,
        &base_trace_rows,
        &extension_trace_rows,
        &composition_trace_rows,
        &trace_ood_eval_map,
        &composition_trace_ood_evals,
        z,
    );

    Ok(fri_verifier.verify(&query_positions, &deep_evaluations)?)
}
