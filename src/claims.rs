use crypto::public_coin::solidity::SolidityVerifierPublicCoin;
use crate::CairoClaim;
use crypto::merkle::LeafVariantMerkleTree;
use crypto::merkle::FriendlyMerkleTree; 
use crypto::hash::pedersen::PedersenHashFn;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use crypto::hash::keccak::Keccak256HashFn;
use crypto::public_coin::cairo::CairoVerifierPublicCoin;

pub const NUM_FRIENDLY_COMMITMENT_LAYERS: u32 = 22;

pub mod starknet {
    use super::*;
    use crypto::hash::keccak::MaskedKeccak256HashFn;
    use layouts::starknet::AirConfig;
    use layouts::starknet::ExecutionTrace;

    pub type EthVerifierClaim =
        CairoClaim<Fp, AirConfig, ExecutionTrace, LeafVariantMerkleTree<MaskedKeccak256HashFn<20>>, SolidityVerifierPublicCoin>;
    pub type CairoVerifierClaim =
        CairoClaim<Fp, AirConfig, ExecutionTrace, FriendlyMerkleTree<NUM_FRIENDLY_COMMITMENT_LAYERS, PedersenHashFn>, CairoVerifierPublicCoin>;
}

pub mod recursive {
    use super::*;
    use layouts::recursive::AirConfig;
    use layouts::recursive::ExecutionTrace;

    pub type EthVerifierClaim =
        CairoClaim<Fp, AirConfig, ExecutionTrace, LeafVariantMerkleTree<Keccak256HashFn>, SolidityVerifierPublicCoin>;
    pub type CairoVerifierClaim =
        CairoClaim<Fp, AirConfig, ExecutionTrace, FriendlyMerkleTree<NUM_FRIENDLY_COMMITMENT_LAYERS, PedersenHashFn>, CairoVerifierPublicCoin>;
}