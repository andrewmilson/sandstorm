//! Claim prover and verifier compatible with Starkware's SHARed Prover (SHARP)

pub mod input;
pub mod merkle;
pub mod prover;
pub mod random;
pub mod utils;
pub mod verifier;

use crate::base;
use crate::sharp::utils::to_montgomery;
use ark_ff::Field;
use ministark::composer::DeepCompositionCoeffs;
use ministark::stark::Stark;
use binary::CompiledProgram;
use random::PublicCoinImpl;
use binary::AirPublicInput;
use layouts::CairoTrace;
use layouts::CairoWitness;
use ministark::Proof;
use layouts::SharpAirConfig;
use ministark::verifier::VerificationError;
use ministark::random::PublicCoin;
use ministark::Air;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use digest::Digest;
use self::input::CairoAuxInput;
use self::merkle::MerkleTreeVariant;

/// Wrapper around a base Cairo claim that has a custom implementation of proof
/// generation and validation to match StarkWare's prover and verifier (SHARP)
pub struct CairoClaim<
    A: SharpAirConfig<Fp = Fp, Fq = Fp>,
    T: CairoTrace<Fp = Fp, Fq = Fp>,
    D: Digest,
>(base::CairoClaim<Fp, A, T, D>);

impl<
        A: SharpAirConfig<Fp = Fp, Fq = Fp, PublicInputs = AirPublicInput<Fp>>,
        T: CairoTrace<Fp = Fp, Fq = Fp>,
        D: Digest,
    > CairoClaim<A, T, D>
{
    pub fn new(program: CompiledProgram<Fp>, air_public_input: AirPublicInput<Fp>) -> Self {
        Self(base::CairoClaim::new(program, air_public_input))
    }

    fn public_coin_seed(&self, air: &Air<A>) -> Vec<u8> {
        let aux_input = CairoAuxInput(air.public_inputs());
        let mut seed = Vec::new();
        for element in aux_input.public_input_elements::<D>() {
            seed.extend_from_slice(&element.to_be_bytes::<32>())
        }
        seed
    }
}

impl<
        A: SharpAirConfig<Fp = Fp, Fq = Fp, PublicInputs = AirPublicInput<Fp>>,
        T: CairoTrace<Fp = Fp, Fq = Fp>,
        D: Digest + Send + Sync + 'static,
    > Stark for CairoClaim<A, T, D>
{
    type Fp = Fp;
    type Fq = Fp;
    type AirConfig = A;
    type Digest = D;
    type MerkleTree = MerkleTreeVariant<D>;
    type PublicCoin = random::PublicCoinImpl<D>;
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

    fn gen_public_coin(&self, air: &Air<A>) -> PublicCoinImpl<D> {
        println!("Generating public coin from SHARP verifier!");
        PublicCoinImpl::new(D::digest(self.public_coin_seed(air)))
    }

    // async fn prove(
    //     &self,
    //     options: ministark::ProofOptions,
    //     witness: Self::Witness,
    // ) -> Result< Proof<Self::Fp, Self::Fq, Self::Digest, Self::MerkleTree>,
    //   ministark::prover::ProvingError,
    // > { self.prove_sharp(options, witness).await
    // }

    fn verify(&self, proof: Proof<Fp, Fp, D, Self::MerkleTree>) -> Result<(), VerificationError> {
        self.verify_sharp(proof)?;
        Ok(())
    }
}
