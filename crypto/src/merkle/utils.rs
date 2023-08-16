use ark_ff::Field;
use ministark::Matrix;
use ministark::hash::ElementHashFn;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[inline]
pub(crate) fn hash_row<H: ElementHashFn<Fp>>(row: &[Fp]) -> H::Digest {
    H::hash_elements(row.iter().copied())
    // let mut hasher = D::new();
    // for v in row {
    //     let v = U256::from(to_montgomery(*v));
    //     hasher.update(v.to_be_bytes::<32>())
    // }
    // hasher.finalize()
}

pub(crate) fn hash_rows<H: ElementHashFn<Fp>>(matrix: &Matrix<Fp>) -> Vec<H::Digest> {
    let num_rows = matrix.num_rows();
    let mut row_hashes = vec![H::Digest::default(); num_rows];

    // #[cfg(not(feature = "parallel"))]
    // let chunk_size = row_hashes.len();
    // #[cfg(feature = "parallel")]
    // let chunk_size = core::cmp::max(
    //     row_hashes.len() / rayon::current_num_threads().next_power_of_two(),
    //     128,
    // );
    const CHUNK_SIZE: usize = 10;

    ark_std::cfg_chunks_mut!(row_hashes, CHUNK_SIZE)
        .enumerate()
        .for_each(|(chunk_offset, chunk)| {
            let offset = CHUNK_SIZE * chunk_offset;

            let mut row_buffer = vec![Fp::ZERO; matrix.num_cols()];

            for (i, row_hash) in chunk.iter_mut().enumerate() {
                matrix.read_row(offset + i, &mut row_buffer);
                *row_hash = hash_row::<H>(&row_buffer);
            }
        });

    row_hashes
}
