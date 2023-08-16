use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_serialize::SerializationError;
use ark_serialize::Valid;
use blake2::Blake2s256;
use ministark::hash::Digest;
use ministark::hash::ElementHashFn;
use ministark::hash::HashFn;
use ministark::merkle::MerkleTreeConfig;
use ministark::merkle::MerkleTreeImpl;
use ministark::utils::SerdeOutput;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use num_bigint::BigUint;
use std::marker::PhantomData;
use crate::hash::blake2s::MaskedBlake2sHashFn;

pub trait MixedHashMerkleTreeConfig: Send + Sync + Sized + 'static {
    const TRANSITION_DEPTH: u32;

    type HighLevelsDigest: Digest;

    type HighLevelsHashFn: HashFn<Digest = Self::HighLevelsDigest>;

    type LowLevelsDigest: Digest;

    type LowLevelsHashFn: HashFn<Digest = Self::LowLevelsDigest>;

    fn hash_boundary(
        n0: &Self::LowLevelsDigest,
        n1: &Self::LowLevelsDigest,
    ) -> Self::HighLevelsDigest;
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MixedDigest<HighLevelsDigest: Digest, LowLevelsDigest: Digest> {
    HighLevel(HighLevelsDigest),
    LowLevel(LowLevelsDigest),
}

impl<HLD: Digest, LLD: Digest> Default for MixedDigest<HLD, LLD> {
    fn default() -> Self {
        Self::HighLevel(HLD::default())
    }
}

impl<HLD: Digest, LLD: Digest> CanonicalSerialize for MixedDigest<HLD, LLD> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        match self {
            Self::HighLevel(d) => {
                0u8.serialize_with_mode(&mut writer, compress)?;
                d.serialize_with_mode(writer, compress)
            }
            Self::LowLevel(d) => {
                1u8.serialize_with_mode(&mut writer, compress)?;
                d.serialize_with_mode(writer, compress)
            }
        }
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        0u8.serialized_size(compress)
            + match self {
                Self::HighLevel(d) => d.serialized_size(compress),
                Self::LowLevel(d) => d.serialized_size(compress),
            }
    }
}

impl<HLD: Digest, LLD: Digest> Valid for MixedDigest<HLD, LLD> {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl<HLD: Digest, LLD: Digest> Digest for MixedDigest<HLD, LLD> {
    fn as_bytes(&self) -> [u8; 32] {
        match self {
            Self::HighLevel(d) => d.as_bytes(),
            Self::LowLevel(d) => d.as_bytes(),
        }
    }
}

impl<HLD: Digest, LLD: Digest> CanonicalDeserialize for MixedDigest<HLD, LLD> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        Ok(
            match u8::deserialize_with_mode(&mut reader, compress, validate)? {
                0 => Self::HighLevel(<_>::deserialize_with_mode(reader, compress, validate)?),
                1 => Self::LowLevel(<_>::deserialize_with_mode(reader, compress, validate)?),
                _ => Err(SerializationError::InvalidData)?,
            },
        )
    }
}

pub struct MixedHashMerkleTreeConfigImpl<C: MixedHashMerkleTreeConfig>(PhantomData<C>);

impl<C: MixedHashMerkleTreeConfig> MerkleTreeConfig for MixedHashMerkleTreeConfigImpl<C> {
    type Digest = MixedDigest<C::HighLevelsDigest, C::LowLevelsDigest>;
    type Leaf = C::LowLevelsDigest;

    fn hash_leaves(depth: u32, l0: &Self::Leaf, l1: &Self::Leaf) -> Self::Digest {
        match depth < C::TRANSITION_DEPTH {
            true => MixedDigest::HighLevel(C::hash_boundary(l0, l1)),
            false => MixedDigest::LowLevel(C::LowLevelsHashFn::merge(l0, l1)),
        }
    }

    fn hash_nodes(depth: u32, n0: &Self::Digest, n1: &Self::Digest) -> Self::Digest {
        use MixedDigest::*;
        match (depth < C::TRANSITION_DEPTH, n0, n1) {
            (false, LowLevel(n0), LowLevel(n1)) => LowLevel(C::LowLevelsHashFn::merge(n0, n1)),
            (true, LowLevel(n0), LowLevel(n1)) => HighLevel(C::hash_boundary(n0, n1)),
            (true, HighLevel(n0), HighLevel(n1)) => HighLevel(C::HighLevelsHashFn::merge(n0, n1)),
            _ => unreachable!(),
        }
    }

    fn security_level_bits() -> u32 {
        C::LowLevelsHashFn::COLLISION_RESISTANCE.min(C::HighLevelsHashFn::COLLISION_RESISTANCE)
    }
}

/// Friendly merkle tree config comprises of an algebraically friendly hash
/// function for higher layers (efficient for verifier) and the Blake2s hash
/// function for lower layers (>100x faster to compute for prover).
pub struct FriendlyMerkleTreeConfig<const N_FRIENDLY_LAYERS: u32, FH: HashFn>(PhantomData<FH>);

impl<const N_FRIENDLY_LAYERS: u32, FriendlyHashFn: ElementHashFn<Fp>> MixedHashMerkleTreeConfig
    for FriendlyMerkleTreeConfig<N_FRIENDLY_LAYERS, FriendlyHashFn>
where
    FriendlyHashFn::Digest: From<Fp>,
{
    type HighLevelsDigest = FriendlyHashFn::Digest;
    type HighLevelsHashFn = FriendlyHashFn;
    type LowLevelsDigest = SerdeOutput<Blake2s256>;
    type LowLevelsHashFn = MaskedBlake2sHashFn<20>;
    const TRANSITION_DEPTH: u32 = N_FRIENDLY_LAYERS;

    fn hash_boundary(
        n0: &SerdeOutput<Blake2s256>,
        n1: &SerdeOutput<Blake2s256>,
    ) -> FriendlyHashFn::Digest {
        let n0 = Fp::from(BigUint::from_bytes_be(n0)).into();
        let n1 = Fp::from(BigUint::from_bytes_be(n1)).into();
        FriendlyHashFn::merge(&n0, &n1)
    }
}

pub type MixedHashMerkleTreeImpl<MixedHashMerkleTreeConfig> =
    MerkleTreeImpl<MixedHashMerkleTreeConfigImpl<MixedHashMerkleTreeConfig>>;
