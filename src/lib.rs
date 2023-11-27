#![feature(allocator_api, array_chunks, int_roundings)]

use ark_ff::Field;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use binary::AirPublicInput;
use binary::CompiledProgram;
use crypto::hash::blake2s::Blake2sHashFn;
use crypto::hash::keccak::CanonicalKeccak256HashFn;
use crypto::hash::pedersen::PedersenHashFn;
use crypto::merkle::mixed::MixedMerkleDigest;
use crypto::public_coin::cairo::CairoVerifierPublicCoin;
use crypto::public_coin::solidity::SolidityVerifierPublicCoin;
use input::CairoAuxInput;
use layouts::CairoTrace;
use layouts::CairoWitness;
use ministark::air::AirConfig;
use ministark::composer::DeepCompositionCoeffs;
use ministark::hash::ElementHashFn;
use ministark::hash::HashFn;
use ministark::merkle::MatrixMerkleTree;
use ministark::merkle::MerkleTree;
use ministark::random::PublicCoin;
use ministark::random::PublicCoinImpl;
use ministark::stark::Stark;
use ministark::Air;
use ministark_gpu::GpuFftField;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use std::marker::PhantomData;

pub mod claims;
pub mod input;

pub struct CairoClaim<
    Fp: GpuFftField + PrimeField,
    A: AirConfig<Fp = Fp, PublicInputs = AirPublicInput<Fp>>,
    T: CairoTrace<Fp = A::Fp, Fq = A::Fq>,
    M: MerkleTree + MatrixMerkleTree<A::Fp> + MatrixMerkleTree<A::Fq>,
    P: CairoPublicCoin<Digest = M::Root, Field = A::Fq>,
> where
    A::Fp: PrimeField,
{
    cairo_program: CompiledProgram<Fp>,
    air_public_input: AirPublicInput<Fp>,
    _phantom: PhantomData<(Fp, A, T, M, P)>,
}

impl<
        Fp: GpuFftField + PrimeField,
        A: AirConfig<Fp = Fp, PublicInputs = AirPublicInput<Fp>>,
        T: CairoTrace<Fp = A::Fp, Fq = A::Fq>,
        M: MerkleTree + MatrixMerkleTree<A::Fp> + MatrixMerkleTree<A::Fq>,
        P: CairoPublicCoin<Digest = M::Root, Field = A::Fq>,
    > CairoClaim<Fp, A, T, M, P>
where
    A::Fp: PrimeField,
{
    pub fn new(cairo_program: CompiledProgram<Fp>, air_public_input: AirPublicInput<Fp>) -> Self {
        Self {
            cairo_program,
            air_public_input,
            _phantom: PhantomData,
        }
    }

    pub fn public_input(&self) -> &AirPublicInput<Fp> {
        &self.air_public_input
    }

    pub fn program(&self) -> &CompiledProgram<Fp> {
        &self.cairo_program
    }
}

impl<
        Fp: GpuFftField + PrimeField,
        A: AirConfig<Fp = Fp, PublicInputs = AirPublicInput<Fp>>,
        T: CairoTrace<Fp = A::Fp, Fq = A::Fq>,
        M: MerkleTree + MatrixMerkleTree<A::Fp> + MatrixMerkleTree<A::Fq>,
        P: CairoPublicCoin<Digest = M::Root, Field = A::Fq>,
    > Stark for CairoClaim<Fp, A, T, M, P>
where
    A::Fp: PrimeField,
{
    type Fp = Fp;
    type Fq = A::Fq;
    type AirConfig = A;
    type Digest = M::Root;
    type PublicCoin = P;
    type Witness = CairoWitness<A::Fp>;
    type MerkleTree = M;
    type Trace = T;

    fn generate_trace(&self, witness: CairoWitness<Fp>) -> T {
        T::new(
            self.cairo_program.clone(),
            self.get_public_inputs(),
            witness,
        )
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
            degree: (Self::Fq::ONE, Self::Fq::ZERO),
        }
    }

    fn gen_public_coin(&self, air: &ministark::Air<Self::AirConfig>) -> Self::PublicCoin {
        P::from_public_input(air.public_inputs())
    }

    fn get_public_inputs(&self) -> AirPublicInput<A::Fp> {
        self.air_public_input.clone()
    }
}

pub trait CairoPublicCoin: PublicCoin {
    fn from_public_input(
        public_input: &AirPublicInput<<Self::Field as Field>::BasePrimeField>,
    ) -> Self;
}

impl<F: Field, H: ElementHashFn<F>> CairoPublicCoin for PublicCoinImpl<F, H> {
    fn from_public_input(
        air_public_input: &AirPublicInput<<Self::Field as Field>::BasePrimeField>,
    ) -> Self {
        // NOTE: this generic implementation is only intended for experimentation so the
        // implementation is rather strange
        let mut bytes = Vec::new();
        air_public_input.serialize_compressed(&mut bytes).unwrap();
        Self::new(H::hash_chunks([&*bytes]))
    }
}

impl CairoPublicCoin for SolidityVerifierPublicCoin {
    fn from_public_input(public_input: &AirPublicInput<Fp>) -> Self {
        let aux_input = CairoAuxInput(public_input);
        let mut seed = Vec::new();
        for element in aux_input.public_input_elements::<CanonicalKeccak256HashFn>() {
            seed.extend_from_slice(&element.to_be_bytes::<32>())
        }
        Self::new(CanonicalKeccak256HashFn::hash_chunks([&*seed]))
    }
}

impl CairoPublicCoin for CairoVerifierPublicCoin {
    fn from_public_input(public_input: &AirPublicInput<Fp>) -> Self {
        let aux_input = CairoAuxInput(public_input);
        let mut seed = Vec::new();
        for element in aux_input.public_input_elements::<PedersenHashFn>() {
            seed.extend_from_slice(&element.to_be_bytes::<32>())
        }
        Self::new(MixedMerkleDigest::LowLevel(Blake2sHashFn::hash_chunks([
            &*seed,
        ])))
    }
}
