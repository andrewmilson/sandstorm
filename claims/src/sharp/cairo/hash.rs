use blake2::Blake2s;

pub struct Blake2sHashFn;

impl HashFn for Blake2sHashFn {
    type Digest = SerdeOutput<Blake2s>;
    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: impl IntoIterator<Item = u8>) -> SerdeOutput<Blake2s> {
        let mut hasher = Blake2s::new();
        for byte in bytes {
            hasher.update([byte]);
        }
        SerdeOutput::new(hasher.finalize())
    }

    fn merge(v0: &SerdeOutput<Blake2s>, v1: &SerdeOutput<Blake2s>) -> SerdeOutput<Blake2s> {
        let mut hasher = Blake2s::new();
        hasher.update(**v0);
        hasher.update(**v1);
        SerdeOutput::new(hasher.finalize())
    }

    fn merge_with_int(seed: &SerdeOutput<Blake2s>, value: u64) -> SerdeOutput<Blake2s> {
        let mut hasher = Blake2s::new();
        hasher.update(**seed);
        hasher.update(value.to_be_bytes());
        SerdeOutput::new(hasher.finalize())
    }
}

impl ElementHashFn<Fp> for Blake2sHashFn {
    fn hash_elements(elements: impl IntoIterator<Item = Fp>) -> SerdeOutput<Blake2s> {
        let mut hasher = Blake2s::new();
        for element in elements {
            hasher.update(U256::from(to_montgomery(element)).to_be_bytes::<32>());
        }
        SerdeOutput::new(hasher.finalize())
    }
}
