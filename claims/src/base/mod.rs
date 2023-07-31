extern crate alloc;

use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use binary::AirPublicInput;
use binary::CompiledProgram;
use layouts::CairoTrace;
use layouts::CairoWitness;
use ministark::air::AirConfig;
use ministark::hash::ElementHashFn;
use ministark::hash::HashFn;
use ministark::merkle::MatrixMerkleTreeImpl;
use ministark::random::PublicCoin;
use ministark::random::PublicCoinImpl;
use ministark::stark::Stark;
use ministark_gpu::GpuFftField;
use std::marker::PhantomData;

pub struct CairoClaim<Fp: PrimeField, A: AirConfig<Fp = Fp>, T: CairoTrace<Fp = Fp>, H: HashFn> {
    program: CompiledProgram<Fp>,
    public_input: AirPublicInput<Fp>,
    _phantom: PhantomData<(A, T, H)>,
}

impl<Fp: GpuFftField + PrimeField, A: AirConfig<Fp = Fp>, T: CairoTrace<Fp = Fp>, H: HashFn>
    CairoClaim<Fp, A, T, H>
{
    pub fn new(program: CompiledProgram<Fp>, public_input: AirPublicInput<Fp>) -> Self {
        Self {
            program,
            public_input,
            _phantom: PhantomData,
        }
    }
}

impl<
        Fp: GpuFftField + PrimeField,
        A: AirConfig<Fp = Fp, PublicInputs = AirPublicInput<Fp>>,
        T: CairoTrace<Fp = Fp, Fq = A::Fq>,
        H: ElementHashFn<Fp> + ElementHashFn<A::Fq>,
    > Stark for CairoClaim<Fp, A, T, H>
{
    type Fp = A::Fp;
    type Fq = A::Fq;
    type AirConfig = A;
    type Digest = H::Digest;
    type PublicCoin = PublicCoinImpl<A::Fq, H>;
    type Witness = CairoWitness<Fp>;
    type MerkleTree = MatrixMerkleTreeImpl<H>;
    type Trace = T;

    fn generate_trace(&self, witness: CairoWitness<Fp>) -> T {
        T::new(self.program.clone(), self.get_public_inputs(), witness)
    }

    fn gen_public_coin(&self, air: &ministark::Air<Self::AirConfig>) -> Self::PublicCoin {
        let mut seed = Vec::new();
        air.public_inputs().serialize_compressed(&mut seed).unwrap();
        air.trace_len().serialize_compressed(&mut seed).unwrap();
        air.options().serialize_compressed(&mut seed).unwrap();
        PublicCoinImpl::new(H::hash_chunks([&*seed]))
    }

    fn get_public_inputs(&self) -> AirPublicInput<Fp> {
        self.public_input.clone()
    }
}
