use crate::layout6::PUBLIC_MEMORY_STEP;
use ark_ff::PrimeField;
use gpu_poly::GpuFftField;
use ministark::StarkExtensionOf;

/// Computes the value of the public memory quotient:
/// Adapted from https://github.com/starkware-libs/starkex-contracts
pub fn compute_public_memory_quotient<Fp: GpuFftField + PrimeField, Fq: StarkExtensionOf<Fp>>(
    z: Fq,
    alpha: Fq,
    trace_len: usize,
    public_memory: &[(usize, Fp)],
    public_memory_padding_address: Fp,
    public_memory_padding_value: Fp,
) -> Fq {
    // the actual number of public memory cells
    let n = public_memory.len();
    // the num of cells allocated for the pub mem (include padding)
    let s = trace_len / PUBLIC_MEMORY_STEP;

    // numerator = (z - (0 + alpha * 0))^S,
    let numerator = z.pow([s as u64]);
    // denominator = \prod_i( z - (addr_i + alpha * value_i) ),
    let denominator = public_memory
        .iter()
        .map(|(a, v)| z - (alpha * v + Fp::from(*a as u64)))
        .product::<Fq>();
    // padding = (z - (padding_addr + alpha * padding_value))^(S - N),
    let padding = (z - (alpha * public_memory_padding_value + public_memory_padding_address))
        .pow([(s - n) as u64]);

    // numerator / (denominator * padding)
    numerator / (denominator * padding)
}
