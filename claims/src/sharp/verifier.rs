extern crate alloc;

use super::CairoClaim;
use ark_ff::PrimeField;
use binary::CairoAuxInput;
use layouts::CairoTrace;
use ministark::air::AirConfig;
use ministark::random::PublicCoin;
use ministark::Verifiable;
use ministark_gpu::GpuFftField;
use sha2::Digest;

impl<
        Fp: GpuFftField + PrimeField,
        A: AirConfig<Fp = Fp, PublicInputs = CairoAuxInput<Fp>>,
        T: CairoTrace<Fp = Fp, Fq = A::Fq>,
        D: Digest,
    > Verifiable for CairoClaim<Fp, A, T, D>
{
    type Fp = A::Fp;
    type Fq = A::Fq;
    type AirConfig = A;
    type Digest = D;

    fn get_public_inputs(&self) -> CairoAuxInput<Fp> {
        self.0.auxiliary_input()
    }

    fn gen_public_coin(&self, air: &ministark::Air<A>) -> PublicCoin<D> {
        println!("Generating public coin from SHARP verifier!");
        let auxiliary_elements = air.public_inputs().serialize_sharp::<D>();
        let mut seed = Vec::new();
        for element in auxiliary_elements {
            seed.extend_from_slice(element.as_le_slice())
        }
        let public_coin = PublicCoin::new(&seed);
        println!("public coin seed is: {:?}", public_coin.seed);
        public_coin
    }
}
