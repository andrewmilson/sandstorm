extern crate alloc;

use std::collections::BTreeMap;

use crate::sharp::input::CairoAuxInput;

use super::CairoClaim;
use ark_ff::Field;
use binary::AirPublicInput;
use binary::MemoryEntry;
use layouts::CairoTrace;
use layouts::SharpAirConfig;
use ministark::air::AirConfig;
use ministark::fri::FriVerifier;
use ministark::verifier::VerificationError;
use ministark::random::PublicCoin;
use ministark::verifier::verify_positions;
use ministark::verifier::deep_composition_evaluations;
use rand::Rng;
use ministark::utils::horner_evaluate;
use ministark::Verifiable;
use ministark::Air;
use ministark::Proof;
use ministark::verifier::ood_constraint_evaluation;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use digest::Digest;
use digest::Output;
use ruint::uint;

pub struct SharpMetadata {
    pub public_memory_product: Fp,
    pub public_memory_alpha: Fp,
    pub public_memory_z: Fp,
}

impl<
        A: SharpAirConfig<Fp = Fp, Fq = Fp, PublicInputs = AirPublicInput<Fp>>,
        T: CairoTrace<Fp = Fp, Fq = Fp>,
        D: Digest,
    > CairoClaim<A, T, D>
{
    pub fn verify_with_artifacts(
        &self,
        proof: Proof<Fp>,
    ) -> Result<SharpMetadata, VerificationError> {
        use VerificationError::*;

        let Proof {
            options,
            base_trace_commitment,
            extension_trace_commitment,
            composition_trace_commitment,
            execution_trace_ood_evals,
            composition_trace_ood_evals,
            trace_queries,
            trace_len,
            fri_proof,
            pow_nonce,
            ..
        } = proof;

        let air = Air::new(trace_len, self.get_public_inputs(), options);
        let mut public_coin = self.gen_public_coin(&air);

        let base_trace_commitment = Output::<D>::from_iter(base_trace_commitment);
        public_coin.reseed(&&*base_trace_commitment);
        let challenges = air.gen_challenges(&mut public_coin);
        let hints = air.gen_hints(&challenges);

        // let public_memory_product = A::public_memory_product(&hints);
        let (public_memory_z, public_memory_alpha) = A::public_memory_challenges(&challenges);
        let mut public_memory_product = Fp::ONE;
        for &MemoryEntry { address, value } in &air.public_inputs().public_memory {
            let address = Fp::from(address);
            public_memory_product *= public_memory_z - (address + value * public_memory_alpha);
        }

        let extension_trace_commitment = extension_trace_commitment.map(|commitment| {
            let commitment = Output::<D>::from_iter(commitment);
            public_coin.reseed(&&*commitment);
            commitment
        });

        let composition_coeffs = air.gen_composition_constraint_coeffs(&mut public_coin);
        let composition_trace_commitment = Output::<D>::from_iter(composition_trace_commitment);
        public_coin.reseed(&&*composition_trace_commitment);

        let z = public_coin.draw::<Fp>();
        public_coin.reseed(&execution_trace_ood_evals);
        // execution trace ood evaluation map
        let trace_ood_eval_map = air
            .trace_arguments()
            .into_iter()
            .zip(execution_trace_ood_evals)
            .collect::<BTreeMap<(usize, isize), Fp>>();
        let calculated_ood_constraint_evaluation = ood_constraint_evaluation::<A>(
            &composition_coeffs,
            &challenges,
            &hints,
            &trace_ood_eval_map,
            &air,
            z,
        );

        public_coin.reseed(&composition_trace_ood_evals);
        let provided_ood_constraint_evaluation = horner_evaluate(&composition_trace_ood_evals, &z);

        if calculated_ood_constraint_evaluation != provided_ood_constraint_evaluation {
            return Err(InconsistentOodConstraintEvaluations);
        }

        let deep_coeffs = air.gen_deep_composition_coeffs(&mut public_coin);
        let fri_verifier = FriVerifier::<Fp, D>::new(
            &mut public_coin,
            options.into_fri_options(),
            fri_proof,
            trace_len - 1,
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
            .collect::<Vec<_>>();
        let extension_trace_rows = if A::NUM_EXTENSION_COLUMNS == 0 {
            Vec::new()
        } else {
            trace_queries
                .extension_trace_values
                .chunks(A::NUM_EXTENSION_COLUMNS)
                .collect::<Vec<_>>()
        };

        let composition_trace_rows = trace_queries
            .composition_trace_values
            .chunks(air.ce_blowup_factor())
            .collect::<Vec<&[Fp]>>();

        // base trace positions
        verify_positions::<D>(
            &base_trace_commitment,
            &query_positions,
            &base_trace_rows,
            trace_queries.base_trace_proofs,
        )
        .map_err(|_| BaseTraceQueryDoesNotMatchCommitment)?;

        if let Some(extension_trace_commitment) = extension_trace_commitment {
            // extension trace positions
            verify_positions::<D>(
                &extension_trace_commitment,
                &query_positions,
                &extension_trace_rows,
                trace_queries.extension_trace_proofs,
            )
            .map_err(|_| ExtensionTraceQueryDoesNotMatchCommitment)?;
        }

        // composition trace positions
        verify_positions::<D>(
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

        fri_verifier.verify(&query_positions, &deep_evaluations)?;

        Ok(SharpMetadata {
            public_memory_product,
            public_memory_z,
            public_memory_alpha,
        })
    }
}

impl<
        A: SharpAirConfig<Fp = Fp, Fq = Fp, PublicInputs = AirPublicInput<Fp>>,
        T: CairoTrace<Fp = Fp, Fq = Fp>,
        D: Digest,
    > Verifiable for CairoClaim<A, T, D>
{
    type Fp = Fp;
    type Fq = Fp;
    type AirConfig = A;
    type Digest = D;

    fn get_public_inputs(&self) -> AirPublicInput<Fp> {
        self.0.get_public_inputs()
    }

    fn gen_public_coin(&self, air: &Air<A>) -> PublicCoin<D> {
        println!("Generating public coin from SHARP verifier!");
        // let auxiliary_elements = air.public_inputs().serialize_sharp::<D>();
        let aux_input = CairoAuxInput(air.public_inputs());
        let mut seed = Vec::new();
        for element in aux_input.public_input_elements::<D>() {
            seed.extend_from_slice(element.as_le_slice())
        }
        let public_coin = PublicCoin::new(&seed);
        println!("public coin seed is: {:?}", public_coin.seed);
        public_coin
    }

    fn verify(&self, proof: Proof<Fp>) -> Result<(), VerificationError> {
        self.verify_with_artifacts(proof)?;
        Ok(())
    }
}
