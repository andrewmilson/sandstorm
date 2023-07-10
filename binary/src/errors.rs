use ruint::aliases::U256;
use std::error::Error;
use std::fmt::Display;

#[derive(Debug, Clone, Copy)]
pub struct InvalidFieldElementError {
    pub value: U256,
    pub modulus: U256,
}

impl Display for InvalidFieldElementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Invalid value: {}, must be less than the field modulus {}",
            self.value, self.modulus
        )
    }
}

impl Error for InvalidFieldElementError {}
