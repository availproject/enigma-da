#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PublicKeyEntry {
    #[prost(uint32, tag = "1")]
    pub id: u32,
    #[prost(enumeration = "ThresholdOperation", tag = "2")]
    pub operation: i32,
    #[prost(enumeration = "ThresholdScheme", tag = "3")]
    pub scheme: i32,
    #[prost(bytes = "vec", tag = "4")]
    pub key: ::prost::alloc::vec::Vec<u8>,
}

#[derive(
    serde::Serialize,
    serde::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum ThresholdScheme {
    ECIESThreshold = 0,
}
impl ThresholdScheme {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ThresholdScheme::ECIESThreshold => "ECIESThreshold",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ECIESThreshold" => Some(Self::ECIESThreshold),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ThresholdOperation {
    Encryption = 0,
}
impl ThresholdOperation {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ThresholdOperation::Encryption => "Encryption",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "Encryption" => Some(Self::Encryption),
            _ => None,
        }
    }
}
