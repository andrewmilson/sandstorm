//! Claim prover and verifier compatible with Starkware's SHARed Prover (SHARP)

pub mod hash;
pub mod input;
pub mod merkle;
pub mod random;
pub mod utils;
pub mod verifier;

use crate::base;
use ark_ff::Field;
use layouts::recursive;
use merkle::FriendlyMerkleTree;
use ministark::hash::HashFn;
use random::CairoPublicCoin;
use ministark::composer::DeepCompositionCoeffs;
use ministark::stark::Stark;
use binary::CompiledProgram;
use binary::AirPublicInput;
use layouts::CairoTrace;
use layouts::CairoWitness;
use ministark::Proof;
use layouts::SharpAirConfig;
use ministark::verifier::VerificationError;
use ministark::random::PublicCoin;
use ministark::Air;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use input::CairoAuxInput;
use layouts::starknet;
use hash::Blake2sHashFn;
use hash::MaskedBlake2sHashFn;
use hash::PedersenHashFn;

use self::merkle::FriendlyCommitment;

pub const NUM_FRIENDLY_LAYERS: u32 = 16;

// List of the hash functions used by StarkWare's verifiers
pub type CairoVerifierMaskedHashFn = MaskedBlake2sHashFn<20>;
pub type CairoFriendlyMerkleTree = FriendlyMerkleTree<NUM_FRIENDLY_LAYERS>;

// List of the targets for SHARP
pub type RecursiveCairoClaim = CairoClaim<recursive::AirConfig, recursive::ExecutionTrace>;

/// Wrapper around a base Cairo claim that has a custom implementation of proof
/// generation and validation to match StarkWare's prover and verifier (SHARP)
pub struct CairoClaim<A: SharpAirConfig<Fp = Fp, Fq = Fp>, T: CairoTrace<Fp = Fp, Fq = Fp>>(
    base::CairoClaim<Fp, A, T, PedersenHashFn>,
);

impl<
        A: SharpAirConfig<Fp = Fp, Fq = Fp, PublicInputs = AirPublicInput<Fp>>,
        T: CairoTrace<Fp = Fp, Fq = Fp>,
    > CairoClaim<A, T>
{
    pub fn new(program: CompiledProgram<Fp>, air_public_input: AirPublicInput<Fp>) -> Self {
        Self(base::CairoClaim::new(program, air_public_input))
    }

    fn public_coin_seed(&self, air: &Air<A>) -> Vec<u8> {
        let aux_input = CairoAuxInput(air.public_inputs());
        let mut seed = Vec::new();
        for element in aux_input.public_input_elements() {
            seed.extend_from_slice(&element.to_be_bytes::<32>())
        }
        seed
    }
}

impl<
        A: SharpAirConfig<Fp = Fp, Fq = Fp, PublicInputs = AirPublicInput<Fp>>,
        T: CairoTrace<Fp = Fp, Fq = Fp>,
    > Stark for CairoClaim<A, T>
{
    type Fp = Fp;
    type Fq = Fp;
    type AirConfig = A;
    type Digest = FriendlyCommitment;
    // type MerkleTree = MerkleTreeVariant<CairoVerifierMaskedHashFn>;
    type MerkleTree = FriendlyMerkleTree<NUM_FRIENDLY_LAYERS>;
    type PublicCoin = CairoPublicCoin;
    type Witness = CairoWitness<Fp>;
    type Trace = T;

    fn get_public_inputs(&self) -> AirPublicInput<Fp> {
        self.0.get_public_inputs()
    }

    fn generate_trace(&self, witness: CairoWitness<Fp>) -> T {
        self.0.generate_trace(witness)
    }

    fn gen_deep_coeffs(
        &self,
        public_coin: &mut Self::PublicCoin,
        air: &Air<Self::AirConfig>,
    ) -> DeepCompositionCoeffs<Self::Fq> {
        let alpha = public_coin.draw();
        let mut coeff_iter = (0..).map(|i| alpha.pow([i]));
        let num_execution_trace = air.trace_arguments().len();
        let num_composition_trace = air.ce_blowup_factor();
        DeepCompositionCoeffs {
            execution_trace: (&mut coeff_iter).take(num_execution_trace).collect(),
            composition_trace: (&mut coeff_iter).take(num_composition_trace).collect(),
            degree: (Fp::ONE, Fp::ZERO),
        }
    }

    fn gen_public_coin(&self, air: &Air<A>) -> CairoPublicCoin {
        println!("Generating public coin from SHARP verifier!");
        CairoPublicCoin::new(FriendlyCommitment::Blake(Blake2sHashFn::hash(
            self.public_coin_seed(air),
        )))
    }

    // async fn prove(
    //     &self,
    //     options: ministark::ProofOptions,
    //     witness: Self::Witness,
    // ) -> Result< Proof<Self::Fp, Self::Fq, Self::Digest, Self::MerkleTree>,
    //   ministark::prover::ProvingError,
    // > { self.prove_sharp(options, witness).await
    // }

    fn verify(
        &self,
        proof: Proof<Self>,
        required_security_level: u32,
    ) -> Result<(), VerificationError> {
        self.verify_sharp(proof, required_security_level)?;
        Ok(())
    }
}
