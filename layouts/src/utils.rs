use ark_ff::Field;
use ark_ff::PrimeField;
use binary::MemoryEntry;
use ministark::utils::FieldVariant;
use ministark::StarkExtensionOf;
use ministark_gpu::GpuFftField;
use num_traits::One;
use num_traits::Zero;
use ruint::aliases::U256;
use ruint::uint;

/// Computes the value of the public memory quotient:
/// Adapted from https://github.com/starkware-libs/starkex-contracts
pub fn compute_public_memory_quotient<
    const PUBLIC_MEMORY_STEP: usize,
    Fp: GpuFftField + PrimeField,
    Fq: StarkExtensionOf<Fp>,
>(
    z: Fq,
    alpha: Fq,
    trace_len: usize,
    public_memory: &[MemoryEntry<Fp>],
    public_memory_padding: MemoryEntry<Fp>,
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
        .map(|e| z - (alpha * e.value + Fp::from(e.address)))
        .product::<Fq>();
    let padding = {
        // padding = (z - (padding_addr + alpha * padding_value))^(S - N),
        let padding_address = Fp::from(public_memory_padding.address);
        let padding_value = public_memory_padding.value;
        (z - (alpha * padding_value + padding_address)).pow([(s - n) as u64])
    };

    // numerator / (denominator * padding)
    numerator / (denominator * padding)
}

/// Source: https://github.com/starkware-libs/starkex-contracts
///
/// # Context
/// The cumulative value is defined using the following recursive formula:
///
/// $$r_1 = 1$$
/// $$r_{j+1} = r_j * (1 + z * u_j) + \alpha * u_j^2$$
///
/// (for $j >= 1$) where $u_j = Dilute(j, spacing, n_{bits}) - Dilute(j-1,
/// spacing, n_{bits})$ and we want to compute the final value
/// $r_{2^{n_{bits}}}$. Note that $u_j$ depends only on the number of trailing
/// zeros in the binary representation of $j$. Specifically,
///
/// $$u_{(1 + 2k) * 2^i} = u_{2^i} =
/// u_{2^{i - 1}} + 2^{i * spacing} - 2^{(i - 1) * spacing + 1}.$$
///
/// The recursive formula can be reduced to a nonrecursive form:
///
/// $$r_j = \prod_{i=1}^{j-1}(1 + z*u_i) + \alpha
///      * \sum_{i=1}^{j-1}(u_i^2 * \prod_{k=i + 1}^{j-1}(1 + z * u_m))$$
///
/// We rewrite this equation to generate a recursive formula that converges
/// in $log(j)$ steps: Denote:
///
/// $$p_i = \prod_{n=1}^{2^i - 1}(1 + z * u_n)$$
/// $$q_i = \sum_{n=1}^{2^i - 1}(u_n^2 * \prod_{m=n + 1}^{2^i-1}(1 + z * u_m))$$
/// $$x_i = u_{2^i}$$
///
/// Clearly $r_{2^i} = p_i + \alpha * q_i$. Moreover, due to the symmetry of the
/// sequence $$u_j, p_i = p_{i - 1} * (1 + z * x_{i - 1}) * p_{i - 1}
/// q_i = q_{i - 1} * (1 + z * x_{i - 1}) * p_{i - 1}
///         + x_{i - 1}^2 * p_{i - 1} + q_{i - 1}$$
///
/// Now we can compute $p_{n_{bits}}$ and $q_{n_{bits}}$ in '$n_{bits}$' steps
/// and we are done.
pub fn compute_diluted_cumulative_value<
    Fp: GpuFftField + PrimeField,
    Fq: StarkExtensionOf<Fp>,
    const N_BITS: usize,
    const SPACING: usize,
>(
    z: Fq,
    alpha: Fq,
) -> Fq {
    assert!(SPACING * N_BITS < Fp::MODULUS_BIT_SIZE as usize);
    assert!(SPACING < u64::BITS as usize);
    let diff_multiplier = Fp::from(1u64 << SPACING);
    let mut diff_x = Fp::from((1u64 << SPACING) - 2);
    // Initialize p, q and x to p_1, q_1 and x_0 respectively.
    let mut p = z + Fq::ONE;
    let mut q = Fq::ONE;
    let mut x = Fq::ONE;
    for _ in 1..N_BITS {
        x += diff_x;
        diff_x *= diff_multiplier;
        // store intermediate values to save multiplications
        let xp = x * p;
        let y = p + z * xp;
        q += q * y + x * xp;
        p *= y;
    }
    p + q * alpha
}

/// Orders memory accesses
/// Accesses must be of the form (address, value)
/// Output is of the form (address, value)
// TODO: make sure supports input, output and builtins
pub fn get_ordered_memory_accesses<const PUBLIC_MEMORY_STEP: usize, F: PrimeField>(
    trace_len: usize,
    accesses: &[MemoryEntry<F>],
    public_memory: &[MemoryEntry<F>],
    public_memory_padding: MemoryEntry<F>,
) -> Vec<MemoryEntry<F>> {
    // the number of cells allocated for the public memory
    let num_pub_mem_cells = trace_len / PUBLIC_MEMORY_STEP;

    // order all memory accesses by address
    // memory accesses are of the form [address, value]
    let mut ordered_accesses = accesses
        .iter()
        .copied()
        .chain((0..num_pub_mem_cells - public_memory.len()).map(|_| public_memory_padding))
        .chain(public_memory.iter().copied())
        .collect::<Vec<MemoryEntry<F>>>();

    ordered_accesses.sort_unstable_by_key(|e| e.address);

    // justification for this is explained in section 9.8 of the Cairo paper https://eprint.iacr.org/2021/1063.pdf.
    // SHARP starts the first address at address 1
    let (zeros, ordered_accesses) = ordered_accesses.split_at(num_pub_mem_cells);
    assert!(zeros.iter().all(|e| e.address.is_zero()));
    assert!(ordered_accesses[0].address.is_one());

    // check memory is "continuous" and "single valued"
    ordered_accesses
        .array_windows()
        .enumerate()
        .for_each(|(i, &[curr, next])| {
            assert!(
                curr == next || curr.address == next.address - 1,
                "mismatch at {i}: curr=({curr:?}), next=({next:?})"
            );
        });

    ordered_accesses.to_vec()
}

pub struct MemoryPool<F>(Vec<MemoryEntry<F>>);

impl<F: PrimeField> MemoryPool<F> {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Pushes a memory access to the pool
    pub fn push(&mut self, entry: MemoryEntry<F>) {
        self.0.push(entry);
    }

    pub fn get_ordered_accesses_with_padding(
        &self,
        trace_len: usize,
        public_memory: Vec<MemoryEntry<F>>,
        padding_entry: MemoryEntry<F>,
    ) -> (Vec<MemoryEntry<F>>, Vec<MemoryEntry<F>>) {
        // order all memory accesses by address
        // memory accesses are of the form (address, value)
        let mut ordered_accesses = self
            .0
            .iter()
            .copied()
            .chain(public_memory)
            .collect::<Vec<MemoryEntry<F>>>();
        ordered_accesses.sort_unstable_by_key(|a| a.address);

        // memory values need to be continuos therefore any gaps
        // e.g. [..., (a:4, v:..), (a:7, v:..), ...] need to
        // be filled with [(a:5, v:..), (a:6, v:..)] as padding.
        let mut padding_accesses = Vec::new();
        for &[a, b] in ordered_accesses.array_windows() {
            for padding_addr in a.address.saturating_add(1)..b.address {
                padding_accesses.push(if a.address == padding_entry.address {
                    padding_entry
                } else {
                    MemoryEntry {
                        address: padding_addr,
                        value: F::ZERO,
                    }
                })
            }
        }

        while padding_accesses.len() + ordered_accesses.len() != trace_len {
            padding_accesses.push(padding_entry);
        }

        // Add padding to the ordered vals
        for v in &padding_accesses {
            ordered_accesses.push(*v);
        }

        // re-sort the accesses.
        ordered_accesses.sort();
        // assert_eq!(trace_len, ordered_accesses.len());
        println!("ol: {}", ordered_accesses.len());
        println!("ol: {}", padding_accesses.len());
        // assert_eq!(trace_len / 8, padding_accesses.len());

        // double check memory is "continuous" and "single valued"
        ordered_accesses
            .array_windows()
            .enumerate()
            .for_each(|(i, &[curr, next])| {
                assert!(
                    curr == next || curr.address == next.address - 1,
                    "mismatch at {i}: curr=({curr:?}), next=({next:?})"
                );
            });

        (ordered_accesses, padding_accesses)
    }
}

impl<F: PrimeField> Default for MemoryPool<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default, Debug, Clone)]
pub struct DilutedCheckPool<const N_BITS: usize, const SPACING: usize>(Vec<u128>);

impl<const N_BITS: usize, const SPACING: usize> DilutedCheckPool<N_BITS, SPACING> {
    pub fn new() -> Self {
        assert!(N_BITS > 0 && N_BITS <= 128);
        assert!(SPACING * N_BITS <= 256);
        Self(Vec::new())
    }

    /// Pushes a binary value without dilution to the pool
    pub fn push(&mut self, v: u128) {
        let bit_len = u128::BITS - v.leading_zeros();
        assert!(bit_len <= N_BITS as u32);
        self.0.push(v)
    }

    /// Pushes a binary value with dilution to the pool
    pub fn push_diluted(&mut self, v: U256) {
        assert!(v.bit_len() <= (N_BITS - 1) * SPACING + 1);
        debug_assert!({
            // check all non diluted bits are zero
            let mut res = v;
            for i in 0..N_BITS {
                res &= !(uint!(1_U256) << (i * SPACING));
            }
            res == U256::ZERO
        });
        let mut res = 0;
        for i in 0..N_BITS {
            let bit: u128 = v.bit(i * SPACING).into();
            res |= bit << i;
        }
        self.push(res)
    }

    /// Returns an ordered list of diluted check values with padding.
    /// Diluted check values, in their regular form, need to be continuos.
    /// For example with SPACING=4:
    /// ```text
    /// [
    ///   0b0000_0000_0001_0001 -> regular form = 3 (0b0011)
    ///   0b0000_0001_0000_0000 -> regular form = 4 (0b0100)
    ///   0b0000_0001_0001_0001 -> regular form = 7 (0b0111)
    ///   0b0001_0000_0000_0000 -> regular form = 8 (0b1000)
    /// ]
    /// ```
    /// needs to be filled with
    /// ```text
    /// [
    ///   0b0000_0001_0000_0001 -> regular form = 5 (0b0101)
    ///   0b0000_0001_0001_0000 -> regular form = 6 (0b0110)
    /// ]
    /// ```
    /// as padding. This padding is added to the ordered list of values and the
    /// padding used is also provided. Output is of the form `(ordered_vals,
    /// padding_vals)` in their regular form without dilution.
    pub fn get_ordered_values_with_padding(&self, min: u128, max: u128) -> (Vec<u128>, Vec<u128>) {
        if self.0.is_empty() {
            return (Vec::new(), (min..=max).collect());
        }

        let mut ordered_vals = self.0.clone();
        ordered_vals.sort_unstable();

        // diluted check values need to be continuos therefore any gaps
        // e.g. [..., 3, 4, 7, 8, ...] need to be filled with [5, 6] as padding.
        let mut padding_vals = Vec::new();

        let first = *ordered_vals.first().unwrap();
        assert!(first >= min);
        for v in min..first {
            padding_vals.push(v);
        }

        let last = *ordered_vals.last().unwrap();
        assert!(last <= max);
        for v in last + 1..=max {
            padding_vals.push(v);
        }

        for &[a, b] in ordered_vals.array_windows() {
            for v in u128::saturating_add(a, 1)..b {
                padding_vals.push(v);
            }
        }

        // Add padding to the ordered vals (res)
        for v in &padding_vals {
            ordered_vals.push(*v);
        }

        // re-sort the values.
        ordered_vals.sort_unstable();

        (ordered_vals, padding_vals)
    }

    pub fn min(&self) -> Option<u128> {
        self.0.iter().min().copied()
    }

    pub fn max(&self) -> Option<u128> {
        self.0.iter().max().copied()
    }
}

#[derive(Default, Debug, Clone)]
pub struct RangeCheckPool(Vec<u16>);

impl RangeCheckPool {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, v: u16) {
        self.0.push(v)
    }

    /// Returns an ordered list of the range check values with padding.
    /// Range check values need to be continuos therefore any gaps e.g.
    /// [..., 3, 4, 7, 8, ...] needs to be filled with [5, 6] as padding. This
    /// padding is added to the ordered list of values and the padding used is
    /// also provided. Output is of the form `(ordered_vals, padding_vals)`.
    pub fn get_ordered_values_with_padding(&self) -> (Vec<u16>, Vec<u16>) {
        let mut ordered_vals = self.0.clone();
        ordered_vals.sort_unstable();

        // range check values need to be continuos therefore any gaps
        // e.g. [..., 3, 4, 7, 8, ...] need to be filled with [5, 6] as padding.
        let mut padding_vals = Vec::new();
        for &[a, b] in ordered_vals.array_windows() {
            for v in u16::saturating_add(a, 1)..b {
                padding_vals.push(v);
            }
        }

        // Add padding to the ordered vals (res)
        for v in &padding_vals {
            ordered_vals.push(*v);
        }

        // re-sort the values.
        ordered_vals.sort_unstable();

        (ordered_vals, padding_vals)
    }

    pub fn min(&self) -> Option<u16> {
        self.0.iter().min().copied()
    }

    pub fn max(&self) -> Option<u16> {
        self.0.iter().max().copied()
    }
}

/// Maps array items into `FieldVariant::Fp`
// TODO: remove. need for const fn.
pub const fn map_into_fp_array<Fp: Field, Fq: Field, const N: usize>(
    arr: [Fp; N],
) -> [FieldVariant<Fp, Fq>; N] {
    let mut res = [FieldVariant::Fp(Fp::ZERO); N];
    let mut i = 0;
    while i < N {
        res[i] = FieldVariant::Fp(arr[i]);
        i += 1;
    }
    res
}
