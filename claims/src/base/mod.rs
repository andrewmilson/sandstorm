extern crate alloc;

use ark_ff::PrimeField;
use binary::AirPublicInput;
use binary::CompiledProgram;
use layouts::CairoTrace;
use layouts::CairoWitness;
use ministark::air::AirConfig;
use ministark::merkle::MatrixMerkleTreeImpl;
use ministark::random::PublicCoinImpl;
use ministark::stark::Stark;
use ministark_gpu::GpuFftField;
use sha2::Digest;
use std::marker::PhantomData;

pub struct CairoClaim<Fp: PrimeField, A: AirConfig<Fp = Fp>, T: CairoTrace<Fp = Fp>, D: Digest> {
    program: CompiledProgram<Fp>,
    public_input: AirPublicInput<Fp>,
    _phantom: PhantomData<(A, T, D)>,
}

impl<Fp: GpuFftField + PrimeField, A: AirConfig<Fp = Fp>, T: CairoTrace<Fp = Fp>, D: Digest>
    CairoClaim<Fp, A, T, D>
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
        D: Digest + Send + Sync + 'static,
    > Stark for CairoClaim<Fp, A, T, D>
{
    type Fp = A::Fp;
    type Fq = A::Fq;
    type AirConfig = A;
    type Digest = D;
    type PublicCoin = PublicCoinImpl<D, A::Fq>;
    type Witness = CairoWitness<Fp>;
    type MerkleTree = MatrixMerkleTreeImpl<D>;
    type Trace = T;

    fn generate_trace(&self, witness: CairoWitness<Fp>) -> T {
        T::new(self.program.clone(), self.get_public_inputs(), witness)
    }

    fn get_public_inputs(&self) -> AirPublicInput<Fp> {
        self.public_input.clone()
    }
}
