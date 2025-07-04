use std::{error::Error, fmt::Display};
pub use proto::new_schemes::ThresholdScheme;

pub trait Serializable: Sized + Clone + PartialEq {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError>;
    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError>;
}
#[derive(Clone, Debug)]
pub enum SchemeError {
    WrongScheme,
    WrongKeyProvided,
    SerializationFailed,
    DeserializationFailed,
    UnknownScheme,
    IdNotFound,
    WrongState,
    InvalidShare,
    SerializationError(String),
    IOError,
    InvalidParams(Option<String>),
    Aborted(String),
    KeyNotFound,
}

impl Error for SchemeError {}

impl Display for SchemeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongScheme => write!(f, "Wrong scheme"),
            Self::WrongKeyProvided => write!(f, "Wrong key provided"),
            Self::SerializationFailed => write!(f, "Serialization failed"),
            Self::DeserializationFailed => write!(f, "Deserialization failed"),
            Self::UnknownScheme => write!(f, "Unknown scheme"),
            Self::IdNotFound => write!(f, "ID not found"),
            Self::WrongState => write!(f, "Wrong state"),
            Self::InvalidShare => write!(f, "Invalid share"),
            Self::SerializationError(s) => write!(f, "Serialization error: {}", s),
            Self::IOError => write!(f, "I/O error"),
            Self::InvalidParams(details) => match details {
                Some(s) => write!(f, "Invalid parameters: {}", s),
                None => write!(f, "Invalid parameters"),
            },
            Self::Aborted(s) => write!(f, "Protocol aborted: {}", s),
            Self::KeyNotFound => write!(f, "Key not found"),
        }
    }
}
