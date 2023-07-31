use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_serialize::SerializationError;
use ark_serialize::Valid;
use blake2::Blake2s256;
use ministark::hash::Digest;
use ministark::hash::ElementHashFn;
use ministark::hash::HashFn;
use ministark::merkle::Error;
use num_bigint::BigUint;
use crate::sharp_to_cairo::CairoVerifierMaskedHashFn;
use ark_ff::Zero;
use ministark::merkle::MatrixMerkleTree;
use ministark::merkle::MerkleProof;
use ministark::merkle::MerkleTree;
use ministark::merkle::MerkleTreeConfig;
use ministark::merkle::MerkleTreeImpl;
use ministark::Matrix;
use ministark::merkle::build_merkle_nodes_default;
use ministark::merkle::verify_proof_default;
use ministark::utils::SerdeOutput;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use std::marker::PhantomData;
use super::hash::Blake2sHashFn;
use super::hash::MaskedBlake2sHashFn;
use super::hash::PedersenDigest;
use super::hash::PedersenHashFn;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FriendlyCommitment {
    Blake(SerdeOutput<Blake2s256>),
    Pedersen(PedersenDigest),
}

impl From<SerdeOutput<Blake2s256>> for FriendlyCommitment {
    fn from(value: SerdeOutput<Blake2s256>) -> Self {
        Self::Blake(value)
    }
}

impl From<PedersenDigest> for FriendlyCommitment {
    fn from(value: PedersenDigest) -> Self {
        Self::Pedersen(value)
    }
}

impl Digest for FriendlyCommitment {
    fn as_bytes(&self) -> [u8; 32] {
        match self {
            Self::Blake(d) => d.as_bytes(),
            Self::Pedersen(d) => d.as_bytes(),
        }
    }
}

impl Default for FriendlyCommitment {
    fn default() -> Self {
        FriendlyCommitment::Pedersen(PedersenDigest::default())
    }
}

impl CanonicalSerialize for FriendlyCommitment {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        match self {
            Self::Blake(d) => {
                0u8.serialize_with_mode(&mut writer, compress)?;
                d.serialize_with_mode(writer, compress)
            }
            Self::Pedersen(d) => {
                1u8.serialize_with_mode(&mut writer, compress)?;
                d.serialize_with_mode(writer, compress)
            }
        }
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        0u8.serialized_size(compress)
            + match self {
                Self::Blake(d) => d.serialized_size(compress),
                Self::Pedersen(d) => d.serialized_size(compress),
            }
    }
}

impl Valid for FriendlyCommitment {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalDeserialize for FriendlyCommitment {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        Ok(
            match u8::deserialize_with_mode(&mut reader, compress, validate)? {
                0 => Self::Blake(<_>::deserialize_with_mode(reader, compress, validate)?),
                1 => Self::Pedersen(<_>::deserialize_with_mode(reader, compress, validate)?),
                _ => Err(SerializationError::InvalidData)?,
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct FriendlyMerkleTree<const N_PEDERSEN_LAYERS: u32> {
    pedersen_nodes: Vec<PedersenDigest>,
    blake_nodes: Vec<SerdeOutput<Blake2s256>>,
    leaves: Vec<SerdeOutput<Blake2s256>>,
}

impl<const N_PEDERSEN_LAYERS: u32> MerkleTree for FriendlyMerkleTree<N_PEDERSEN_LAYERS> {
    type Proof = MerkleProof<FriendlyCommitment, SerdeOutput<Blake2s256>>;
    type Root = FriendlyCommitment;

    fn prove(&self, mut index: usize) -> Result<Self::Proof, Error> {
        let num_layers = self.leaves.len().ilog2();
        let num_blake_layers = num_layers.saturating_sub(N_PEDERSEN_LAYERS);
        let num_pedersen_layers = num_layers.min(N_PEDERSEN_LAYERS);

        // TODO: batch proofs
        // TODO: omit leaves[index]?
        let leaf = self.leaves[index].clone();
        let sibling = self.leaves[index ^ 1].clone();
        index = (index + (1 << num_layers)) >> 1;

        let blake_path = {
            let mut path = Vec::new();
            // TODO: can remove this line
            while index >= 2.max(1 << num_pedersen_layers) {
                path.push(self.blake_nodes[index ^ 1].clone());
                index >>= 1;
            }
            path
        };

        let pedersen_path = {
            let mut path = Vec::new();
            // TODO: can remove this line
            while index > 1 {
                path.push(self.pedersen_nodes[index ^ 1]);
                index >>= 1;
            }
            path
        };

        let path = [
            blake_path
                .into_iter()
                .map(FriendlyCommitment::from)
                .collect::<Vec<_>>(),
            pedersen_path
                .into_iter()
                .map(FriendlyCommitment::from)
                .collect::<Vec<_>>(),
        ]
        .concat();

        Ok(MerkleProof::new(leaf, sibling, path))
    }

    fn root(&self) -> FriendlyCommitment {
        if N_PEDERSEN_LAYERS == 0 {
            self.blake_nodes[1].clone().into()
        } else {
            self.pedersen_nodes[1].into()
        }
    }

    fn verify(root: &Self::Root, proof: &Self::Proof, mut index: usize) -> Result<(), Error> {
        let height = proof.height() as u32;
        let (leaf_lhs, leaf_rhs) = if index % 2 == 0 {
            (proof.leaf(), proof.sibling())
        } else {
            (proof.sibling(), proof.leaf())
        };

        let (final_blake_lhs, final_blake_rhs) = {
            let num_blake_layers = height.saturating_sub(N_PEDERSEN_LAYERS);
            if num_blake_layers == 0 {
                (leaf_lhs.clone(), leaf_rhs.clone())
            } else {
                let mut running_hash = CairoVerifierMaskedHashFn::merge(leaf_lhs, leaf_rhs);
                index >>= 1;
                let remaining_blake_layers = num_blake_layers
                    .saturating_sub(if N_PEDERSEN_LAYERS == 0 { 2 } else { 1 })
                    as usize;
                for node in &proof.path()[..remaining_blake_layers] {
                    let node = match node {
                        FriendlyCommitment::Blake(d) => d,
                        _ => return Err(Error::InvalidProof),
                    };

                    running_hash = if index % 2 == 0 {
                        CairoVerifierMaskedHashFn::merge(&running_hash, &node)
                    } else {
                        CairoVerifierMaskedHashFn::merge(&node, &running_hash)
                    };
                    index >>= 1;
                }

                let node = match &proof.path()[remaining_blake_layers] {
                    FriendlyCommitment::Blake(d) => d.clone(),
                    _ => return Err(Error::InvalidProof),
                };

                if index % 2 == 0 {
                    (running_hash, node)
                } else {
                    (node, running_hash)
                }
            }
        };

        let running_hash = if N_PEDERSEN_LAYERS == 0 {
            CairoVerifierMaskedHashFn::merge(&final_blake_lhs, &final_blake_rhs).into()
        } else {
            let num_pedersen_layers = height.min(N_PEDERSEN_LAYERS);
            let lhs = Fp::from(BigUint::from_bytes_be(&final_blake_lhs));
            let rhs = Fp::from(BigUint::from_bytes_be(&final_blake_rhs));
            let mut running_hash =
                PedersenHashFn::merge(&PedersenDigest(lhs), &PedersenDigest(rhs));
            index >>= 1;
            let pedersen_node_offset = proof
                .path()
                .len()
                .saturating_sub((num_pedersen_layers as usize).saturating_sub(1));
            for node in &proof.path()[pedersen_node_offset..] {
                let node = match node {
                    FriendlyCommitment::Pedersen(d) => d,
                    _ => return Err(Error::InvalidProof),
                };

                running_hash = if index % 2 == 0 {
                    PedersenHashFn::merge(&running_hash, &node)
                } else {
                    PedersenHashFn::merge(&node, &running_hash)
                };
                index >>= 1;
            }
            running_hash.into()
        };

        if *root == running_hash {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        }
    }

    fn security_level_bits() -> u32 {
        CairoVerifierMaskedHashFn::COLLISION_RESISTANCE.min(PedersenHashFn::COLLISION_RESISTANCE)
    }
}

impl<const N_PEDERSEN_LAYERS: u32> MatrixMerkleTree<Fp> for FriendlyMerkleTree<N_PEDERSEN_LAYERS> {
    fn from_matrix(m: &Matrix<Fp>) -> Self {
        let leaves = hash_rows::<CairoVerifierMaskedHashFn>(m);
        let num_layers = leaves.len().ilog2();
        let num_blake_layers = num_layers.saturating_sub(N_PEDERSEN_LAYERS);

        let blake_nodes = if num_blake_layers == 0 {
            Vec::new()
        } else {
            let n = 1 << num_layers;
            let mut nodes = vec![SerdeOutput::<Blake2s256>::default(); n];

            // generate first layer of nodes from leaf nodes
            for i in 0..n / 2 {
                nodes[n / 2 + i] =
                    CairoVerifierMaskedHashFn::merge(&leaves[i * 2], &leaves[i * 2 + 1]);
            }

            // generate remaining nodes
            for i in ((1 << N_PEDERSEN_LAYERS)..n / 2).rev() {
                nodes[i] = CairoVerifierMaskedHashFn::merge(&nodes[i * 2], &nodes[i * 2 + 1]);
            }

            nodes
        };

        let pedersen_nodes = if N_PEDERSEN_LAYERS == 0 {
            Vec::new()
        } else {
            let num_pedersen_layers = N_PEDERSEN_LAYERS.min(num_layers);
            let n = 1 << num_pedersen_layers;
            let blake_leaves = if num_blake_layers == 0 {
                &leaves
            } else {
                &blake_nodes[n..n * 2]
            };
            let mut nodes = vec![PedersenDigest::default(); n];

            // generate first layer of nodes from leaf nodes
            for i in 0..n / 2 {
                let lhs = Fp::from(BigUint::from_bytes_be(&blake_leaves[i * 2]));
                let rhs = Fp::from(BigUint::from_bytes_be(&blake_leaves[i * 2 + 1]));
                nodes[n / 2 + i] =
                    PedersenHashFn::merge(&PedersenDigest(lhs), &PedersenDigest(rhs));
            }

            // generate remaining nodes
            for i in (0..n / 2).rev() {
                nodes[i] = PedersenHashFn::merge(&nodes[i * 2], &nodes[i * 2 + 1]);
            }

            nodes
        };

        // let num_pedersen_layers = N_PEDERSEN_LAYERS.min(num_layers);
        Self {
            pedersen_nodes,
            blake_nodes,
            leaves,
        }
    }

    fn prove_row(&self, row_idx: usize) -> Result<Self::Proof, Error> {
        self.prove(row_idx)
    }

    fn verify_row(
        root: &Self::Root,
        row_idx: usize,
        row: &[Fp],
        proof: &Self::Proof,
    ) -> Result<(), Error> {
        let row_hash = hash_row::<CairoVerifierMaskedHashFn>(row);
        if proof.leaf() == &row_hash {
            Self::verify(root, proof, row_idx)
        } else {
            Err(Error::InvalidProof)
        }
    }
}

#[derive(Default)]
pub struct UnhashedLeafConfig<H>(PhantomData<H>);

impl<H: ElementHashFn<Fp>> MerkleTreeConfig for UnhashedLeafConfig<H> {
    type Digest = H::Digest;
    type Leaf = Fp;

    fn hash_leaves(l0: &Fp, l1: &Fp) -> H::Digest {
        H::hash_elements([*l0, *l1])
    }

    fn build_merkle_nodes(leaves: &[Self::Leaf]) -> Vec<Self::Digest> {
        build_merkle_nodes_default::<Self, H>(leaves)
    }

    fn verify_proof(
        root: &Self::Digest,
        proof: &MerkleProof<H::Digest, Fp>,
        index: usize,
    ) -> Result<(), Error> {
        verify_proof_default::<Self, H>(root, proof, index)
    }

    fn security_level_bits() -> u32 {
        H::COLLISION_RESISTANCE
    }
}

#[derive(Default)]
pub struct HashedLeafConfig<H>(PhantomData<H>);

impl<H: ElementHashFn<Fp>> MerkleTreeConfig for HashedLeafConfig<H> {
    type Digest = H::Digest;
    type Leaf = H::Digest;

    fn hash_leaves(l0: &H::Digest, l1: &H::Digest) -> H::Digest {
        H::merge(l0, l1)
    }

    fn build_merkle_nodes(leaves: &[Self::Leaf]) -> Vec<Self::Digest> {
        build_merkle_nodes_default::<Self, H>(leaves)
    }

    fn verify_proof(
        root: &Self::Digest,
        proof: &MerkleProof<H::Digest, H::Digest>,
        index: usize,
    ) -> Result<(), Error> {
        verify_proof_default::<Self, H>(root, proof, index)
    }

    fn security_level_bits() -> u32 {
        H::COLLISION_RESISTANCE
    }
}

pub enum MerkleTreeVariantProof<H: ElementHashFn<Fp>> {
    Hashed(MerkleProof<H::Digest, H::Digest>),
    Unhashed(MerkleProof<H::Digest, Fp>),
}

impl<H: ElementHashFn<Fp>> Clone for MerkleTreeVariantProof<H> {
    fn clone(&self) -> Self {
        match self {
            Self::Hashed(proof) => Self::Hashed(proof.clone()),
            Self::Unhashed(proof) => Self::Unhashed(proof.clone()),
        }
    }
}

impl<H: ElementHashFn<Fp>> CanonicalSerialize for MerkleTreeVariantProof<H> {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        match self {
            Self::Hashed(proof) => {
                0u8.serialize_with_mode(&mut writer, compress)?;
                proof.serialize_with_mode(writer, compress)
            }
            Self::Unhashed(proof) => {
                1u8.serialize_with_mode(&mut writer, compress)?;
                proof.serialize_with_mode(writer, compress)
            }
        }
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        1 + match self {
            Self::Hashed(proof) => proof.serialized_size(compress),
            Self::Unhashed(proof) => proof.serialized_size(compress),
        }
    }
}

impl<H: ElementHashFn<Fp>> Valid for MerkleTreeVariantProof<H> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}

impl<H: ElementHashFn<Fp>> CanonicalDeserialize for MerkleTreeVariantProof<H> {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let variant = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(match variant {
            0 => Self::Hashed(<_>::deserialize_with_mode(reader, compress, validate)?),
            1 => Self::Unhashed(<_>::deserialize_with_mode(reader, compress, validate)?),
            _ => Err(ark_serialize::SerializationError::InvalidData)?,
        })
    }
}

pub enum MerkleTreeVariant<H: ElementHashFn<Fp>> {
    Hashed(MerkleTreeImpl<HashedLeafConfig<H>>),
    Unhashed(MerkleTreeImpl<UnhashedLeafConfig<H>>),
}

impl<H: ElementHashFn<Fp>> Clone for MerkleTreeVariant<H> {
    fn clone(&self) -> Self {
        match self {
            Self::Hashed(mt) => Self::Hashed(mt.clone()),
            Self::Unhashed(mt) => Self::Unhashed(mt.clone()),
        }
    }
}

impl<H: ElementHashFn<Fp>> MerkleTree for MerkleTreeVariant<H> {
    type Proof = MerkleTreeVariantProof<H>;
    type Root = H::Digest;

    fn root(&self) -> Self::Root {
        match self {
            Self::Hashed(mt) => mt.root(),
            Self::Unhashed(mt) => mt.root(),
        }
    }

    fn prove(&self, index: usize) -> Result<MerkleTreeVariantProof<H>, Error> {
        Ok(match self {
            Self::Hashed(mt) => MerkleTreeVariantProof::Hashed(mt.prove(index)?),
            Self::Unhashed(mt) => MerkleTreeVariantProof::Unhashed(mt.prove(index)?),
        })
    }

    fn verify(root: &Self::Root, proof: &Self::Proof, index: usize) -> Result<(), Error> {
        match proof {
            MerkleTreeVariantProof::Hashed(proof) => {
                MerkleTreeImpl::<HashedLeafConfig<H>>::verify(root, proof, index)
            }
            MerkleTreeVariantProof::Unhashed(proof) => {
                MerkleTreeImpl::<UnhashedLeafConfig<H>>::verify(root, proof, index)
            }
        }
    }

    fn security_level_bits() -> u32 {
        H::COLLISION_RESISTANCE
    }
}

impl<H: ElementHashFn<Fp>> MatrixMerkleTree<Fp> for MerkleTreeVariant<H> {
    fn from_matrix(matrix: &Matrix<Fp>) -> Self {
        match matrix.num_cols() {
            0 => unreachable!(),
            1 => {
                // matrix is single column so don't bother with leaf hashes
                let leaves = matrix[0].to_vec();
                Self::Unhashed(MerkleTreeImpl::new(leaves).unwrap())
            }
            _ => {
                let row_hashes = hash_rows::<H>(matrix);
                Self::Hashed(MerkleTreeImpl::new(row_hashes).unwrap())
            }
        }
    }

    fn prove_row(&self, row_idx: usize) -> Result<MerkleTreeVariantProof<H>, Error> {
        self.prove(row_idx)
    }

    fn verify_row(
        root: &H::Digest,
        row_idx: usize,
        row: &[Fp],
        proof: &MerkleTreeVariantProof<H>,
    ) -> Result<(), Error> {
        match (row, proof) {
            (&[], _) => Err(Error::InvalidProof),
            (&[leaf], MerkleTreeVariantProof::Unhashed(proof)) => {
                if *proof.leaf() == leaf {
                    MerkleTreeImpl::<UnhashedLeafConfig<H>>::verify(root, proof, row_idx)
                } else {
                    Err(Error::InvalidProof)
                }
            }
            (row, MerkleTreeVariantProof::Hashed(proof)) => {
                let row_hash = hash_row::<H>(row);
                if proof.leaf() == &row_hash {
                    MerkleTreeImpl::<HashedLeafConfig<H>>::verify(root, proof, row_idx)
                } else {
                    Err(Error::InvalidProof)
                }
            }
            _ => Err(Error::InvalidProof),
        }
    }
}

#[inline]
fn hash_row<H: ElementHashFn<Fp>>(row: &[Fp]) -> H::Digest {
    H::hash_elements(row.iter().copied())
    // let mut hasher = D::new();
    // for v in row {
    //     let v = U256::from(to_montgomery(*v));
    //     hasher.update(v.to_be_bytes::<32>())
    // }
    // hasher.finalize()
}

fn hash_rows<H: ElementHashFn<Fp>>(matrix: &Matrix<Fp>) -> Vec<H::Digest> {
    let num_rows = matrix.num_rows();
    let mut row_hashes = vec![H::Digest::default(); num_rows];

    #[cfg(not(feature = "parallel"))]
    let chunk_size = row_hashes.len();
    #[cfg(feature = "parallel")]
    let chunk_size = core::cmp::max(
        row_hashes.len() / rayon::current_num_threads().next_power_of_two(),
        128,
    );

    ark_std::cfg_chunks_mut!(row_hashes, chunk_size)
        .enumerate()
        .for_each(|(chunk_offset, chunk)| {
            let offset = chunk_size * chunk_offset;

            let mut row_buffer = vec![Fp::zero(); matrix.num_cols()];

            for (i, row_hash) in chunk.iter_mut().enumerate() {
                matrix.read_row(offset + i, &mut row_buffer);
                *row_hash = hash_row::<H>(&row_buffer);
            }
        });

    row_hashes
}

#[cfg(test)]
mod tests {
    use super::super::hash::Blake2sHashFn;
    use super::FriendlyMerkleTree;
    use super::MerkleTree;
    use super::MerkleTreeVariant;
    use ark_ff::MontFp as Fp;
    use blake2::Blake2s256;
    use digest::Output;
    use ministark::merkle::Error;
    use ministark::merkle::MatrixMerkleTree;
    use ministark::utils::GpuAllocator;
    use ministark::Matrix;
    use std::mem::size_of;

    #[test]
    fn verify_unhashed_leaves() -> Result<(), Error> {
        let leaves = [Fp!("1"), Fp!("2"), Fp!("3"), Fp!("4")];
        let single_column_matrix = Matrix::new(vec![leaves.to_vec_in(GpuAllocator)]);
        let tree = MerkleTreeVariant::<Blake2sHashFn>::from_matrix(&single_column_matrix);
        let commitment = tree.root();
        let i = 3;

        let proof = tree.prove_row(i)?;

        assert!(matches!(tree, MerkleTreeVariant::Unhashed(_)));
        MerkleTreeVariant::verify_row(&commitment, i, &[leaves[i]], &proof)
    }

    // #[test]
    // fn verify_hashed_leaves() -> Result<(), Error> {
    //     let leaves = [Fp!("1"), Fp!("2"), Fp!("3"), Fp!("4")];
    //     let multi_column_matrix = Matrix::new(vec![
    //         leaves.to_vec_in(GpuAllocator),
    //         leaves.to_vec_in(GpuAllocator),
    //     ]);
    //     let tree =
    // MerkleTreeVariant::<Blake2sHashFn>::from_matrix(&multi_column_matrix);
    //     let commitment = tree.root();
    //     let i = 3;

    //     let proof = tree.prove_row(i)?;

    //     assert!(matches!(tree, MerkleTreeVariant::Hashed(_)));
    //     MerkleTreeVariant::verify_row(&commitment, i, &[leaves[i], leaves[i]],
    // &proof) }

    #[test]
    fn friendly_merkle_tree_without_pedersen() -> Result<(), Error> {
        const REVEAL_INDEX: usize = 3;
        const NUM_PEDERSEN_LAYERS: u32 = 0;
        let matrix = Matrix::new(vec![[
            Fp!("0"),
            Fp!("1"),
            Fp!("2"),
            Fp!("3"),
            Fp!("4"),
            Fp!("5"),
            Fp!("6"),
            Fp!("7"),
        ]
        .to_vec_in(GpuAllocator)]);
        let merkle_tree = FriendlyMerkleTree::<NUM_PEDERSEN_LAYERS>::from_matrix(&matrix);
        let root = merkle_tree.root();

        let proof = merkle_tree.prove_row(REVEAL_INDEX)?;

        FriendlyMerkleTree::<NUM_PEDERSEN_LAYERS>::verify(&root, &proof, REVEAL_INDEX)
    }

    #[test]
    fn friendly_merkle_tree_with_single_pedersen_layer() -> Result<(), Error> {
        const REVEAL_INDEX: usize = 3;
        const NUM_PEDERSEN_LAYERS: u32 = 1;
        let matrix = Matrix::new(vec![[
            Fp!("0"),
            Fp!("1"),
            Fp!("2"),
            Fp!("3"),
            Fp!("4"),
            Fp!("5"),
            Fp!("6"),
            Fp!("7"),
        ]
        .to_vec_in(GpuAllocator)]);
        let merkle_tree = FriendlyMerkleTree::<NUM_PEDERSEN_LAYERS>::from_matrix(&matrix);
        let root = merkle_tree.root();

        let proof = merkle_tree.prove_row(REVEAL_INDEX)?;

        FriendlyMerkleTree::<NUM_PEDERSEN_LAYERS>::verify(&root, &proof, REVEAL_INDEX)
    }

    #[test]
    fn friendly_merkle_tree_with_multiple_pedersen_layers() -> Result<(), Error> {
        const REVEAL_INDEX: usize = 3;
        const NUM_PEDERSEN_LAYERS: u32 = 3;
        let matrix = Matrix::new(vec![[
            Fp!("0"),
            Fp!("1"),
            Fp!("2"),
            Fp!("3"),
            Fp!("4"),
            Fp!("5"),
            Fp!("6"),
            Fp!("7"),
        ]
        .to_vec_in(GpuAllocator)]);
        let merkle_tree = FriendlyMerkleTree::<NUM_PEDERSEN_LAYERS>::from_matrix(&matrix);
        let root = merkle_tree.root();

        let proof = merkle_tree.prove_row(REVEAL_INDEX)?;

        FriendlyMerkleTree::<NUM_PEDERSEN_LAYERS>::verify(&root, &proof, REVEAL_INDEX)
    }

    #[test]
    fn print_size() {
        println!("Size of hash {}", size_of::<Output<Blake2s256>>());
    }
}
