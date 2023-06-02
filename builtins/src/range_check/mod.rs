use binary::RangeCheckInstance;
use ruint::aliases::U256;
use ruint::uint;

#[derive(Clone, Debug)]
pub struct InstanceTrace<const NUM_PARTS: usize> {
    pub instance: RangeCheckInstance,
    pub parts: [u16; NUM_PARTS],
}

impl<const NUM_PARTS: usize> InstanceTrace<NUM_PARTS> {
    pub fn new(instance: RangeCheckInstance) -> Self {
        let value = instance.value;
        assert!(value < uint!(1_U256) << (NUM_PARTS * 16));

        // decompose value into u16 parts
        let mask = U256::from(u16::MAX);
        let mut parts = [0; NUM_PARTS];
        for (i, part) in parts.iter_mut().enumerate() {
            *part = ((value >> ((NUM_PARTS - i - 1) * 16)) & mask)
                .try_into()
                .unwrap();
        }

        Self { instance, parts }
    }
}
