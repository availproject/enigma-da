use crate::key_type::ThresholdDecryptionError;
use std::{error::Error, fmt::Display};
pub use theta_proto::new_schemes::ThresholdScheme;

pub type SessionId = [u8; 32];

pub trait Serializable: Sized + Clone + PartialEq {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError>;
    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError>;
}
#[derive(Clone, Debug)]
pub enum SchemeError {
    WrongGroup,
    WrongScheme,
    WrongKeyProvided,
    SerializationFailed,
    DeserializationFailed,
    CurveDoesNotSupportPairings,
    ParamsNotSet,
    IdNotFound,
    IncompatibleGroup,
    WrongState,
    PreviousRoundNotExecuted,
    InvalidRound,
    InvalidShare,
    ProtocolNotFinished,
    NotReadyForNextRound,
    MessageNotSpecified,
    MessageAlreadySpecified,
    SerializationError(String),
    UnknownScheme,
    UnknownGroupString,
    UnknownGroup,
    IOError,
    InvalidParams(Option<String>),
    Aborted(String),
    KeyNotFound,
    MacFailure,
    NoMoreCommitments,
    ThresholdDecryptionError(ThresholdDecryptionError),
}

impl Error for SchemeError {}

impl Display for SchemeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongGroup => write!(f, "Wrong group"),
            Self::WrongScheme => write!(f, "Wrong scheme"),
            Self::WrongKeyProvided => write!(f, "Wrong key provided"),
            Self::SerializationFailed => write!(f, "Serialization failed"),
            Self::DeserializationFailed => write!(f, "Deserialization failed"),
            Self::CurveDoesNotSupportPairings => write!(f, "Curve does not support pairings"),
            Self::ParamsNotSet => write!(f, "Parameters not set"),
            Self::IdNotFound => write!(f, "ID not found"),
            Self::IncompatibleGroup => write!(f, "Incompatible group"),
            Self::WrongState => write!(f, "Wrong state"),
            Self::PreviousRoundNotExecuted => write!(f, "Previous round not executed"),
            Self::InvalidRound => write!(f, "Invalid round"),
            Self::InvalidShare => write!(f, "Invalid share"),
            Self::ProtocolNotFinished => write!(f, "Protocol not finished"),
            Self::NotReadyForNextRound => write!(f, "Not ready for next round"),
            Self::MessageNotSpecified => write!(f, "Message not specified"),
            Self::MessageAlreadySpecified => write!(f, "Message already specified"),
            Self::SerializationError(s) => write!(f, "Serialization error: {}", s),
            Self::UnknownScheme => write!(f, "Unknown scheme"),
            Self::UnknownGroupString => write!(f, "Unknown group string"),
            Self::UnknownGroup => write!(f, "Unknown group"),
            Self::IOError => write!(f, "I/O error"),
            Self::InvalidParams(details) => match details {
                Some(s) => write!(f, "Invalid parameters: {}", s),
                None => write!(f, "Invalid parameters"),
            },
            Self::Aborted(s) => write!(f, "Protocol aborted: {}", s),
            Self::MacFailure => write!(f, "MAC Failure"),
            Self::KeyNotFound => write!(f, "Key not found"),
            Self::NoMoreCommitments => write!(f, "No more commitments available"),
            Self::ThresholdDecryptionError(err) => {
                write!(f, "Threshold decryption error: {}", err)
            }
        }
    }
}
