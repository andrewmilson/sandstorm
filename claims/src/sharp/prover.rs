extern crate alloc;

use super::CairoClaim;
use binary::AirPublicInput;
use layouts::CairoTrace;
use layouts::CairoWitness;
use layouts::SharpAirConfig;
use ministark::air::AirConfig;
use ministark::Provable;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use sha2::Digest;

impl<
        A: SharpAirConfig<Fp = Fp, Fq = Fp, PublicInputs = AirPublicInput<Fp>>,
        T: CairoTrace<Fp = Fp, Fq = Fp>,
        D: Digest,
    > Provable for CairoClaim<A, T, D>
{
    type Witness = CairoWitness<Fp>;
    type Trace = T;

    fn generate_trace(&self, witness: CairoWitness<Fp>) -> T {
        self.0.generate_trace(witness)
    }
}
