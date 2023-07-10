extern crate alloc;

use ark_ff::PrimeField;
use binary::AirPublicInput;
use binary::CompiledProgram;
use layouts::CairoTrace;
use layouts::CairoWitness;
use ministark::air::AirConfig;
use ministark::Provable;
use ministark::Verifiable;
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
        D: Digest,
    > Verifiable for CairoClaim<Fp, A, T, D>
{
    type Fp = A::Fp;
    type Fq = A::Fq;
    type AirConfig = A;
    type Digest = D;

    fn get_public_inputs(&self) -> AirPublicInput<Fp> {
        self.public_input.clone()
    }
}

impl<
        Fp: GpuFftField + PrimeField,
        A: AirConfig<Fp = Fp, PublicInputs = AirPublicInput<Fp>>,
        T: CairoTrace<Fp = Fp, Fq = A::Fq>,
        D: Digest,
    > Provable for CairoClaim<Fp, A, T, D>
{
    type Witness = CairoWitness<Fp>;
    type Trace = T;

    fn generate_trace(&self, witness: CairoWitness<Fp>) -> T {
        T::new(self.program.clone(), self.get_public_inputs(), witness)
    }
}
