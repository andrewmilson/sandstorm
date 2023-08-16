use std::ops::Deref;

use binary::BitwiseInstance;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use num_bigint::BigUint;
use ruint::aliases::U256;

#[derive(Clone, Debug)]
pub struct InstanceTrace<const SPACING: usize> {
    pub instance: BitwiseInstance,
    pub x: Fp,
    pub y: Fp,
    pub x_and_y: Fp,
    pub x_xor_y: Fp,
    pub x_or_y: Fp,
    pub x_partition: Partition256<SPACING>,
    pub y_partition: Partition256<SPACING>,
    pub x_and_y_partition: Partition256<SPACING>,
    pub x_xor_y_partition: Partition256<SPACING>,
}

impl<const SPACING: usize> InstanceTrace<SPACING> {
    pub fn new(instance: BitwiseInstance) -> Self {
        let BitwiseInstance { x, y, .. } = instance;
        let x_and_y = x & y;
        let x_xor_y = x ^ y;
        let x_or_y = x | y;

        let x_partition = Partition256::new(x);
        let y_partition = Partition256::new(y);
        let x_and_y_partition = Partition256::new(x_and_y);
        let x_xor_y_partition = Partition256::new(x_xor_y);

        let x = BigUint::from(x).into();
        let y = BigUint::from(y).into();
        let x_and_y = BigUint::from(x_and_y).into();
        let x_xor_y = BigUint::from(x_xor_y).into();
        let x_or_y = BigUint::from(x_or_y).into();

        Self {
            instance,
            x,
            y,
            x_and_y,
            x_xor_y,
            x_or_y,
            x_partition,
            y_partition,
            x_and_y_partition,
            x_xor_y_partition,
        }
    }
}

/// Partitions of a 64 bit integer
/// For example to break up the 64 bit binary integer `v` with spacing 4:
/// ```text
///  v = 0b1100_1010_0110_1001_0101_0100_0100_0000_0100_0010_0001_0010_1111_0111_1100
/// s0 = 0b0000_0000_0000_0001_0001_0000_0000_0000_0000_0000_0001_0000_0001_0001_0000
/// s1 = 0b0000_0001_0001_0000_0000_0000_0000_0000_0000_0001_0000_0001_0001_0001_0000
/// s2 = 0b0001_0000_0001_0000_0001_0001_0001_0000_0001_0000_0000_0000_0001_0001_0001
/// s3 = 0b0001_0001_0000_0001_0000_0000_0000_0000_0000_0000_0000_0000_0001_0000_0001
/// ```
/// note that `v = s0 * 2^0 + s1 * 2^1 + s2 * 2^2 + s3 * 2^3`.
#[derive(Clone, Copy, Debug)]
pub struct Partition64<const SPACING: usize> {
    segments: [u64; SPACING],
}

impl<const SPACING: usize> Partition64<SPACING> {
    const N_BITS: usize = u64::BITS as usize / SPACING;

    pub fn new(v: u64) -> Self {
        let mut segments = [0; SPACING];
        for b in 0..Self::N_BITS {
            for (s, segment) in segments.iter_mut().enumerate() {
                let bit = (v >> (b * SPACING + s)) & 1;
                *segment |= bit << (b * SPACING);
            }
        }
        Self { segments }
    }
}

impl<const SPACING: usize> Deref for Partition64<SPACING> {
    type Target = [u64; SPACING];

    fn deref(&self) -> &Self::Target {
        &self.segments
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Partition128<const SPACING: usize> {
    pub low: Partition64<SPACING>,
    pub high: Partition64<SPACING>,
}

impl<const SPACING: usize> Partition128<SPACING> {
    pub fn new(v: u128) -> Self {
        Self {
            low: Partition64::new(v as u64),
            high: Partition64::new((v >> 64) as u64),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Partition256<const SPACING: usize> {
    pub low: Partition128<SPACING>,
    pub high: Partition128<SPACING>,
}

impl<const SPACING: usize> Partition256<SPACING> {
    pub fn new(v: U256) -> Self {
        // least significant first
        let [l0, l1, l2, l3] = v.into_limbs();
        Self {
            low: Partition128::new(((l1 as u128) << 64) + l0 as u128),
            high: Partition128::new(((l3 as u128) << 64) + l2 as u128),
        }
    }
}

/// Dilutes input v by interspersing `SPACING - 1` many 0s between bits
/// E.g. `SPACING=4, v=0b1111, diluted_v=0001000100010001`
pub fn dilute<const SPACING: usize>(v: U256) -> U256 {
    let mut res = U256::ZERO;
    for i in 0..U256::BITS / SPACING {
        res.set_bit(i * SPACING, v.bit(i));
    }
    res
}

#[cfg(test)]
mod tests {
    use crate::bitwise::dilute;
    use ruint::aliases::U256;

    #[test]
    fn dilute_works() {
        let input = U256::from(0b101u32);

        assert_eq!(U256::from(0b0001_0000_0001u32), dilute::<4>(input))
    }
}
