extern crate alloc;

use super::CairoClaim;
use ark_ff::PrimeField;
use binary::CairoAuxInput;
use layouts::CairoTrace;
use layouts::CairoWitness;
use ministark::air::AirConfig;
use ministark::Provable;
use ministark_gpu::GpuFftField;
use sha2::Digest;

impl<
        Fp: GpuFftField + PrimeField,
        A: AirConfig<Fp = Fp, PublicInputs = CairoAuxInput<Fp>>,
        T: CairoTrace<Fp = Fp, Fq = A::Fq>,
        D: Digest,
    > Provable for CairoClaim<Fp, A, T, D>
{
    type Witness = CairoWitness<Fp>;
    type Trace = T;

    fn generate_trace(&self, witness: CairoWitness<Fp>) -> T {
        self.0.generate_trace(witness)
    }
}
