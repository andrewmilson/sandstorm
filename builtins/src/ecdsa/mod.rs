use binary::EcdsaInstance;
use ruint::aliases::U256;
use ruint::uint;

#[derive(Clone, Debug)]
pub struct InstanceTrace {
    pub instance: EcdsaInstance,
}

impl InstanceTrace {
    pub fn new(instance: EcdsaInstance) -> Self {
        Self { instance }
    }
}
