extern crate alloc;

use super::CairoClaim;
use binary::CairoAuxInput;
use layouts::CairoTrace;
use ministark::air::AirConfig;
use ministark::random::PublicCoin;
use ministark::Verifiable;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use sha2::Digest;

impl<
        A: AirConfig<Fp = Fp, Fq = Fp, PublicInputs = CairoAuxInput<Fp>>,
        T: CairoTrace<Fp = Fp, Fq = Fp>,
        D: Digest,
    > Verifiable for CairoClaim<A, T, D>
{
    type Fp = Fp;
    type Fq = Fp;
    type AirConfig = A;
    type Digest = D;

    fn get_public_inputs(&self) -> CairoAuxInput<Fp> {
        self.0.get_public_inputs()
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
