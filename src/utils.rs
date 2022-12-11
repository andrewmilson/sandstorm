use gpu_poly::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::Fp;
use crate::air::PUBLIC_MEMORY_STEP;
use ark_ff::Field;

/// Computes the value of the public memory quotient:
///     numerator / (denominator * padding)
/// where:
///     numerator = (z - (0 + alpha * 0))^S,
///     denominator = \prod_i( z - (addr_i + alpha * value_i) ),
///     padding = (z - (padding_addr + alpha * padding_value))^(S - N),
///     N is the actual number of public memory cells,
///     and S is the num of cells allocated for the pub mem (include padding).
/// Adapted from https://github.com/starkware-libs/starkex-contracts
pub fn compute_public_memory_quotient(
    z: Fp,
    alpha: Fp,
    trace_len: usize,
    public_memory: &[(usize, Fp)],
) -> Fp {
    let n = public_memory.len();
    let s = trace_len / PUBLIC_MEMORY_STEP;

    let numerator = z.pow([s as u64]);
    let denominator = public_memory
        .iter()
        .map(|(a, v)| z - (Fp::from(*a as u64) + alpha * v))
        .product::<Fp>();
    // TODO: I think there's still work to do here.
    // what if the last cycle uses public memory?
    // TODO: should have public input padding address and padding value
    let padding = z.pow([(s - n) as u64]);

    numerator / (denominator * padding)
}
