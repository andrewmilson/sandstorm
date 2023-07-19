use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_serialize::Valid;
use digest::Digest;
use digest::Output;
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
use ruint::aliases::U256;
use std::marker::PhantomData;

use super::utils::to_montgomery;

#[derive(Default)]
pub struct UnhashedLeafConfig<D>(PhantomData<(D, Fp)>);

impl<D: Digest + Send + Sync + 'static> MerkleTreeConfig for UnhashedLeafConfig<D> {
    type Digest = D;
    type Leaf = Fp;

    fn hash_leaves(l0: &Fp, l1: &Fp) -> Output<D> {
        let mut hasher = D::new();
        hasher.update(U256::from(to_montgomery(*l0)).to_be_bytes::<32>());
        hasher.update(U256::from(to_montgomery(*l1)).to_be_bytes::<32>());
        hasher.finalize()
    }
}

#[derive(Default)]
pub struct HashedLeafConfig<D>(PhantomData<D>);

impl<D: Digest + Send + Sync + 'static> MerkleTreeConfig for HashedLeafConfig<D> {
    type Digest = D;
    type Leaf = SerdeOutput<D>;

    fn hash_leaves(l0: &SerdeOutput<D>, l1: &SerdeOutput<D>) -> Output<D> {
        let mut hasher = D::new();
        hasher.update(&**l0);
        hasher.update(&**l1);
        hasher.finalize()
    }
}

pub enum MerkleTreeVariantProof<D: Digest + Send + Sync + 'static> {
    Hashed(MerkleProof<HashedLeafConfig<D>>),
    Unhashed(MerkleProof<UnhashedLeafConfig<D>>),
}

impl<D: Digest + Send + Sync + 'static> Clone for MerkleTreeVariantProof<D> {
    fn clone(&self) -> Self {
        match self {
            Self::Hashed(proof) => Self::Hashed(proof.clone()),
            Self::Unhashed(proof) => Self::Unhashed(proof.clone()),
        }
    }
}

impl<D: Digest + Send + Sync + 'static> CanonicalSerialize for MerkleTreeVariantProof<D> {
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

impl<D: Digest + Send + Sync + 'static> Valid for MerkleTreeVariantProof<D> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}

impl<D: Digest + Send + Sync + 'static> CanonicalDeserialize for MerkleTreeVariantProof<D> {
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

pub enum MerkleTreeVariant<D: Digest + Send + Sync + 'static> {
    Hashed(MerkleTreeImpl<HashedLeafConfig<D>>),
    Unhashed(MerkleTreeImpl<UnhashedLeafConfig<D>>),
}

impl<D: Digest + Send + Sync + 'static> Clone for MerkleTreeVariant<D> {
    fn clone(&self) -> Self {
        match self {
            Self::Hashed(mt) => Self::Hashed(mt.clone()),
            Self::Unhashed(mt) => Self::Unhashed(mt.clone()),
        }
    }
}

impl<D: Digest + Send + Sync + 'static> MerkleTree for MerkleTreeVariant<D> {
    type Proof = MerkleTreeVariantProof<D>;
    type Root = Output<D>;

    fn root(&self) -> &Self::Root {
        match self {
            Self::Hashed(mt) => mt.root(),
            Self::Unhashed(mt) => mt.root(),
        }
    }

    fn prove(&self, index: usize) -> Result<MerkleTreeVariantProof<D>, Error> {
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

impl<D: Digest + Send + Sync + 'static> MatrixMerkleTree<Fp> for MerkleTreeVariant<D> {
    fn from_matrix(matrix: &Matrix<Fp>) -> Self {
        match matrix.num_cols() {
            0 => unreachable!(),
            1 => {
                // matrix is single column so don't bother with leaf hashes
                let leaves = matrix[0].to_vec();
                Self::Unhashed(MerkleTreeImpl::new(leaves).unwrap())
            }
            _ => {
                let row_hashes = hash_rows::<D>(matrix);
                let leaves = row_hashes.into_iter().map(SerdeOutput::new).collect();
                Self::Hashed(MerkleTreeImpl::new(leaves).unwrap())
            }
        }
    }

    fn prove_row(&self, row_idx: usize) -> Result<MerkleTreeVariantProof<D>, Error> {
        self.prove(row_idx)
    }

    fn verify_row(
        root: &Output<D>,
        row_idx: usize,
        row: &[Fp],
        proof: &MerkleTreeVariantProof<D>,
    ) -> Result<(), Error> {
        match (row, proof) {
            (&[], _) => Err(Error::InvalidProof),
            (&[leaf], MerkleTreeVariantProof::Unhashed(proof)) => {
                if *proof.leaf() == leaf {
                    MerkleTreeImpl::<UnhashedLeafConfig<D>>::verify(root, proof, row_idx)
                } else {
                    Err(Error::InvalidProof)
                }
            }
            (row, MerkleTreeVariantProof::Hashed(proof)) => {
                let row_hash = hash_row::<D>(row);
                if **proof.leaf() == row_hash {
                    MerkleTreeImpl::<HashedLeafConfig<D>>::verify(root, proof, row_idx)
                } else {
                    Err(Error::InvalidProof)
                }
            }
            _ => Err(Error::InvalidProof),
        }
    }
}

#[inline]
fn hash_row<D: Digest>(row: &[Fp]) -> Output<D> {
    let mut hasher = D::new();
    for v in row {
        let v = U256::from(to_montgomery(*v));
        hasher.update(v.to_be_bytes::<32>())
    }
    hasher.finalize()
}

fn hash_rows<D: Digest>(matrix: &Matrix<Fp>) -> Vec<Output<D>> {
    let num_rows = matrix.num_rows();
    let mut row_hashes = vec![Output::<D>::default(); num_rows];

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
                *row_hash = hash_row::<D>(&row_buffer);
            }
        });

    row_hashes
}

#[cfg(test)]
mod tests {
    use super::MerkleTree;
    use super::MerkleTreeVariant;
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
        let tree = MerkleTreeVariant::<Keccak256>::from_matrix(&single_column_matrix);
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
        let tree = MerkleTreeVariant::<Keccak256>::from_matrix(&multi_column_matrix);
        let commitment = tree.root();
        let i = 3;

        let proof = tree.prove_row(i)?;

        assert!(matches!(tree, MerkleTreeVariant::Hashed(_)));
        MerkleTreeVariant::verify_row(commitment, i, &[leaves[i], leaves[i]], &proof)
    }
}
