use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use ministark::hash::HashFn;
use ministark::random::PublicCoin;
use sandstorm_crypto::hash::blake2s::Blake2sHashFn;
use sandstorm_crypto::hash::keccak::Keccak256HashFn;
use sandstorm_crypto::merkle::mixed::MixedMerkleDigest;
use sandstorm_crypto::public_coin::cairo::CairoVerifierPublicCoin;
use sandstorm_crypto::public_coin::solidity::SolidityVerifierPublicCoin;

const PROOF_OF_WORK_BITS: u8 = 22;

fn bench_proof_of_work<P: PublicCoin>(c: &mut Criterion, p: P, id: &str) {
    c.bench_function(&format!("{id}/PoW/{PROOF_OF_WORK_BITS}_bits"), |b| {
        b.iter(|| p.grind_proof_of_work(PROOF_OF_WORK_BITS).unwrap())
    });
}

fn proof_of_work_benches(c: &mut Criterion) {
    {
        let seed = Keccak256HashFn::hash(*b"Hello World!");
        let public_coin = SolidityVerifierPublicCoin::new(seed);
        bench_proof_of_work(c, public_coin, "public_coin/solidity_verifier");
    }
    {
        let seed = MixedMerkleDigest::LowLevel(Blake2sHashFn::hash(*b"Hello World!"));
        let public_coin = CairoVerifierPublicCoin::new(seed);
        bench_proof_of_work(c, public_coin, "public_coin/cairo_verifier");
    }
}

criterion_group!(benches, proof_of_work_benches);
criterion_main!(benches);
