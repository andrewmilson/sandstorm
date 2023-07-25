use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_serialize::Valid;
use digest::Digest;
use ministark::hash::ElementHashFn;
use ministark::hash::HashFn;
use ministark::merkle::Error;
use ark_ff::Zero;
use ministark::merkle::MatrixMerkleTree;
use ministark::merkle::MerkleProof;
use ministark::merkle::MerkleTree;
use ministark::merkle::MerkleTreeConfig;
use ministark::merkle::MerkleTreeImpl;
use ministark::utils::SerdeOutput;
use ministark::Matrix;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use std::iter::zip;
use std::marker::PhantomData;

pub const HASH_MASK: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[inline]
pub fn mask_bytes(bytes: &mut [u8], mask: &[u8]) {
    for (byte, mask) in zip(bytes, mask) {
        *byte &= mask;
    }
}

#[derive(Default)]
pub struct UnhashedLeafConfig<H>(PhantomData<H>);

impl<H: ElementHashFn<Fp>> MerkleTreeConfig for UnhashedLeafConfig<H> {
    type Digest = H::Digest;
    type HashFn = H;
    type Leaf = Fp;

    fn hash_leaves(l0: &Fp, l1: &Fp) -> H::Digest {
        H::hash_elements([*l0, *l1])
    }

    // #[inline]
    // fn pre_process_node_hash(hash: &mut H::Digest) {
    //     mask_bytes(hash, &HASH_MASK);
    // }
}

#[derive(Default)]
pub struct HashedLeafConfig<H>(PhantomData<H>);

impl<H: ElementHashFn<Fp>> MerkleTreeConfig for HashedLeafConfig<H> {
    type Digest = H::Digest;
    type HashFn = H;
    type Leaf = H::Digest;

    fn hash_leaves(l0: &H::Digest, l1: &H::Digest) -> H::Digest {
        H::merge(l0, l1)
    }

    // #[inline]
    // fn pre_process_node_hash(hash: &mut Output<D>) {
    //     mask_bytes(hash, &HASH_MASK);
    // }
}

pub enum MerkleTreeVariantProof<H: ElementHashFn<Fp>> {
    Hashed(MerkleProof<HashedLeafConfig<H>>),
    Unhashed(MerkleProof<UnhashedLeafConfig<H>>),
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

    fn root(&self) -> &Self::Root {
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
            MerkleTreeVariantProof::Hashed(proof) => MerkleTreeImpl::verify(root, proof, index),
            MerkleTreeVariantProof::Unhashed(proof) => MerkleTreeImpl::verify(root, proof, index),
        }
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
                let mut row_hashes = hash_rows::<H>(matrix);
                for hash in &mut row_hashes {
                    // mask_bytes(hash, &HASH_MASK);
                }
                // let leaves = row_hashes.into_iter().map(SerdeOutput::new).collect();
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
                let mut row_hash = hash_row::<H>(row);
                // mask_bytes(&mut row_hash, &HASH_MASK);
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
    use super::MerkleTree;
    use super::MerkleTreeVariant;
    use crate::sharp::hash::Keccak256HashFn;
    use ark_ff::MontFp as Fp;
    use ministark::merkle::Error;
    use ministark::merkle::MatrixMerkleTree;
    use ministark::utils::GpuAllocator;
    use ministark::Matrix;
    use sha3::Keccak256;

    #[test]
    fn verify_unhashed_leaves() -> Result<(), Error> {
        let leaves = [Fp!("1"), Fp!("2"), Fp!("3"), Fp!("4")];
        let single_column_matrix = Matrix::new(vec![leaves.to_vec_in(GpuAllocator)]);
        let tree = MerkleTreeVariant::<Keccak256HashFn>::from_matrix(&single_column_matrix);
        let commitment = tree.root();
        let i = 3;

        let proof = tree.prove_row(i)?;

        assert!(matches!(tree, MerkleTreeVariant::Unhashed(_)));
        MerkleTreeVariant::verify_row(commitment, i, &[leaves[i]], &proof)
    }

    #[test]
    fn verify_hashed_leaves() -> Result<(), Error> {
        let leaves = [Fp!("1"), Fp!("2"), Fp!("3"), Fp!("4")];
        let multi_column_matrix = Matrix::new(vec![
            leaves.to_vec_in(GpuAllocator),
            leaves.to_vec_in(GpuAllocator),
        ]);
        let tree = MerkleTreeVariant::<Keccak256HashFn>::from_matrix(&multi_column_matrix);
        let commitment = tree.root();
        let i = 3;

        let proof = tree.prove_row(i)?;

        assert!(matches!(tree, MerkleTreeVariant::Hashed(_)));
        MerkleTreeVariant::verify_row(commitment, i, &[leaves[i], leaves[i]], &proof)
    }
}
