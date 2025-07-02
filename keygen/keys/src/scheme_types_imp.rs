use crate::interface::SchemeError;
use theta_proto::new_schemes::{ThresholdOperation, ThresholdScheme};

pub trait SchemeDetails {
    fn get_id(&self) -> u8;
    fn from_id(id: u8) -> Option<ThresholdScheme>;
    fn parse_string(scheme: &str) -> Result<ThresholdScheme, SchemeError>;
    fn get_operation(&self) -> ThresholdOperation;
}

impl SchemeDetails for ThresholdScheme {
    fn get_id(&self) -> u8 {
        *self as u8
    }

    fn from_id(id: u8) -> Option<Self> {
        ThresholdScheme::from_i32(id as i32)
    }

    fn parse_string(scheme: &str) -> Result<Self, SchemeError> {
        match scheme {
            "elgamal_threshold" => Ok(Self::ECIESThreshold),

            _ => Err(SchemeError::UnknownScheme),
        }
    }

    fn get_operation(&self) -> ThresholdOperation {
        match self {
            Self::ECIESThreshold => ThresholdOperation::Encryption,
        }
    }
}
