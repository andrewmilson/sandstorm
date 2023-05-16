use crate::layout6::PUBLIC_MEMORY_STEP;
use ark_ff::Field;
use ark_ff::PrimeField;
use binary::CompiledProgram;
use binary::Memory;
use binary::RegisterState;
use binary::RegisterStates;
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

/// Returns the (unpadded) range check column values
/// Currently only offset (off_dst, off_op0, off_op1) are used
/// Output is of the form `(ordered_vals, padding_vals)`
pub fn ordered_range_check_values<F: Field>(
    num_cycles: usize,
    mem: &Memory<F>,
    register_states: &RegisterStates,
) -> (Vec<usize>, Vec<usize>) {
    let mut res = Vec::new();
    for &RegisterState { pc, .. } in register_states.iter() {
        // TODO: this seems wasteful. Could combine with public_memory_padding_address?
        let word = mem[pc].unwrap();
        let cycle_rc_values = [word.get_off_dst(), word.get_off_op0(), word.get_off_op1()];
        res.push(cycle_rc_values);
    }

    // The trace is padded to a power-of-two by copying the trace rows of the last
    // cycle. These copied values need to be accounted for in the range check.
    res.resize(num_cycles, *res.last().unwrap());

    // Get the individual range check values in order
    let mut res = res.flatten().to_vec();
    res.sort();

    // range check values need to be continuos therefore any gaps
    // e.g. [..., 3, 4, 7, 8, ...] need to be filled with [5, 6] as padding.
    let mut padding = Vec::new();
    for &[a, b] in res.array_windows() {
        for v in a + 1..b {
            padding.push(v);
        }
    }

    // Add padding to the ordered vals (res)
    for v in &padding {
        res.push(*v);
    }

    // re-sort the values.
    // padding is already sorted.
    res.sort();

    (res, padding)
}

/// Orders memory accesses
/// Accesses must be of the form (address, value)
/// Output is of the form (address, value)
// TODO: make sure supports input, output and builtins
pub fn get_ordered_memory_accesses<F: PrimeField>(
    trace_len: usize,
    accesses: &[(F, F)],
    program: &CompiledProgram,
) -> Vec<(F, F)> {
    // the number of cells allocated for the public memory
    let num_pub_mem_cells = trace_len / PUBLIC_MEMORY_STEP;
    let pub_mem = program.get_public_memory::<F>();
    let pub_mem_accesses = pub_mem.iter().map(|&(a, v)| ((a as u64).into(), v));
    let (padding_address, padding_value) = program.get_padding_address_and_value();
    let padding_entry = ((padding_address as u64).into(), padding_value);

    // order all memory accesses by address
    // memory accesses are of the form [address, value]
    let mut ordered_accesses = accesses
        .iter()
        .copied()
        .chain((0..num_pub_mem_cells - pub_mem_accesses.len()).map(|_| padding_entry))
        .chain(pub_mem_accesses)
        .collect::<Vec<(F, F)>>();

    ordered_accesses.sort();

    // justification for this is explained in section 9.8 of the Cairo paper https://eprint.iacr.org/2021/1063.pdf.
    // SHARP starts the first address at address 1
    let (zeros, ordered_accesses) = ordered_accesses.split_at(num_pub_mem_cells);
    assert!(zeros.iter().all(|(a, v)| a.is_zero() && v.is_zero()));
    assert!(ordered_accesses[0].0.is_one());

    // check memory is "continuous" and "single valued"
    ordered_accesses
        .array_windows()
        .enumerate()
        .for_each(|(i, &[(a, v), (a_next, v_next)])| {
            assert!(
                (a == a_next && v == v_next) || a == a_next - F::one(),
                "mismatch at {i}: a={a}, v={v}, a_next={a_next}, v_next={v_next}"
            );
        });

    ordered_accesses.to_vec()
}
