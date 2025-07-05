#![allow(non_snake_case)]
use super::key_type::{ECIESPrivateKey, ECIESPublicKey, ECIESVerifier};
use crate::interface::{SchemeError, Serializable};
use crate::scheme_types_imp::SchemeDetails;
use asn1::ParseError;
use asn1::WriteError;
use base64::{Engine as _, engine::general_purpose};
use ecies::PublicKey as EciesPublicKey;
use k256::{ProjectivePoint, Scalar};
use proto::new_schemes::{ThresholdOperation, ThresholdScheme};
use rasn::AsnType;
use serde::ser::SerializeSeq;
use vsss_rs_std::{PedersenVerifier, Share};

#[derive(AsnType, Clone, PartialEq, Debug)]
#[rasn(enumerated)]
pub enum PublicKey {
    ECIESThreshold(ECIESPublicKey),
}
impl Eq for PublicKey {}
impl Serializable for PublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        match self {
            Self::ECIESThreshold(key) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::ECIESThreshold.get_id())?;

                        let bytes = key.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }
                        w.write_element(&bytes.unwrap().as_slice())?;
                        Ok(())
                    }))
                });

                if result.is_err() {
                    return Err(SchemeError::SerializationFailed);
                }

                return Ok(result.unwrap());
            }
        }
    }
    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            return d.read_element::<asn1::Sequence>()?.parse(|d| {
                let scheme = ThresholdScheme::from_id(d.read_element::<u8>()?);
                let bytes = d.read_element::<&[u8]>()?.to_vec();

                if scheme.is_none() {
                    return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                }

                let key;
                match scheme.unwrap() {
                    ThresholdScheme::ECIESThreshold => {
                        let r = ECIESPublicKey::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        key = Ok(Self::ECIESThreshold(r.unwrap()));
                    }
                }
                return key;
            });
        });
        if result.is_err() {
            return Err(SchemeError::DeserializationFailed);
        }
        return Ok(result.unwrap());
    }
}
impl PublicKey {
    pub fn get_n(&self) -> u8 {
        match self {
            PublicKey::ECIESThreshold(pk) => pk.n,
        }
    }
    pub fn get_k(&self) -> u8 {
        match self {
            PublicKey::ECIESThreshold(pk) => pk.k,
        }
    }
    pub fn get_app_id(&self) -> u32 {
        match self {
            PublicKey::ECIESThreshold(pk) => pk.app_id.clone(),
        }
    }

    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            PublicKey::ECIESThreshold(_) => ThresholdScheme::ECIESThreshold,
        }
    }
    pub fn get_operation(&self) -> ThresholdOperation {
        self.get_scheme().get_operation()
    }

    pub fn pem(&self) -> Result<String, SchemeError> {
        let r = self.to_bytes();
        if let Ok(bytes) = r {
            let encoded_url = general_purpose::URL_SAFE.encode(bytes);
            return Ok(encoded_url);
        }
        Err(r.unwrap_err())
    }

    pub fn from_pem(pem: &str) -> Result<Self, SchemeError> {
        let r = general_purpose::URL_SAFE.decode(pem);
        if let Ok(bytes) = r {
            return PublicKey::from_bytes(&bytes);
        }

        Err(SchemeError::DeserializationFailed)
    }

    pub fn get_pk(&self) -> &EciesPublicKey {
        match self {
            PublicKey::ECIESThreshold(key) => key.get_pk(),
        }
    }
}
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // deserializer.deserialize_bytes(BytesVisitor)
        deserializer.deserialize_seq(PublicKeyVisitor)
    }
}

impl serde::Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match Serializable::to_bytes(self) {
            // Ok(key_bytes) => { serializer.serialize_bytes(&key_bytes) },
            Ok(key_bytes) => {
                let mut seq = serializer.serialize_seq(Some(key_bytes.len()))?;
                for element in key_bytes.iter() {
                    seq.serialize_element(element)?;
                }
                seq.end()
            }
            Err(err) => Err(serde::ser::Error::custom(format!(
                "Could not serialize PublicKey. err: {:?}",
                err
            ))),
        }
    }
}
#[derive(AsnType, Clone, Debug)]
#[rasn(enumerated)]
pub enum PrivateKeyShare {
    ECIESThreshold(ECIESPrivateKey),
}
impl Eq for PrivateKeyShare {}
impl PartialEq for PrivateKeyShare {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::ECIESThreshold(l0), Self::ECIESThreshold(r0)) => l0.eq(r0),
        }
    }
}
impl Serializable for PrivateKeyShare {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        match self {
            Self::ECIESThreshold(key) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        w.write_element(&ThresholdScheme::ECIESThreshold.get_id())?;

                        let bytes = key.to_bytes();
                        if bytes.is_err() {
                            return Err(WriteError::AllocationError);
                        }

                        w.write_element(&bytes.unwrap().as_slice())?;
                        Ok(())
                    }))
                });

                if result.is_err() {
                    return Err(SchemeError::SerializationFailed);
                }

                Ok(result.unwrap())
            }
        }
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            d.read_element::<asn1::Sequence>()?.parse(|d| {
                let scheme = ThresholdScheme::from_id(d.read_element::<u8>()?);
                let bytes = d.read_element::<&[u8]>()?.to_vec();

                if scheme.is_none() {
                    return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                }

                match scheme.unwrap() {
                    ThresholdScheme::ECIESThreshold => {
                        let r = ECIESPrivateKey::from_bytes(&bytes);
                        if r.is_err() {
                            return Err(ParseError::new(asn1::ParseErrorKind::InvalidValue));
                        }

                        Ok(Self::ECIESThreshold(r.unwrap()))
                    } // _ => Err(ParseError::new(asn1::ParseErrorKind::InvalidValue)), // In case of mismatch
                }
            })
        });

        if result.is_err() {
            println!("{}", result.as_ref().err().unwrap().to_string());
            return Err(SchemeError::DeserializationFailed);
        }

        Ok(result.unwrap())
    }
}
struct PrivateKeyVisitor;
impl<'de> serde::de::Visitor<'de> for PrivateKeyVisitor {
    type Value = PrivateKeyShare;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of bytes")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut key_vec = Vec::new();
        while let Ok(Some(next)) = seq.next_element() {
            key_vec.push(next);
        }
        let key = PrivateKeyShare::from_bytes(&key_vec); //TODO: fix
        Ok(key.unwrap())
    }
}

impl<'de> serde::Deserialize<'de> for PrivateKeyShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // deserializer.deserialize_bytes(BytesVisitor)
        deserializer.deserialize_seq(PrivateKeyVisitor)
    }
}
impl serde::Serialize for PrivateKeyShare {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match Serializable::to_bytes(self) {
            // Ok(key_bytes) => { serializer.serialize_bytes(&key_bytes) },
            Ok(key_bytes) => {
                let mut seq = serializer.serialize_seq(Some(key_bytes.len()))?;
                for element in key_bytes.iter() {
                    seq.serialize_element(element)?;
                }
                seq.end()
            }
            Err(err) => Err(serde::ser::Error::custom(format!(
                "Could not serialize PrivateKey. err: {:?}",
                err
            ))),
        }
    }
}

impl PrivateKeyShare {
    pub fn get_scheme(&self) -> ThresholdScheme {
        match self {
            PrivateKeyShare::ECIESThreshold(_) => ThresholdScheme::ECIESThreshold,
        }
    }
    pub fn get_share_id(&self) -> u8 {
        match self {
            PrivateKeyShare::ECIESThreshold(key) => key.get_share_id(),
        }
    }
    pub fn get_threshold(&self) -> u8 {
        match self {
            PrivateKeyShare::ECIESThreshold(key) => key.get_threshold(),
        }
    }
    pub fn get_public_key(&self) -> PublicKey {
        match self {
            PrivateKeyShare::ECIESThreshold(key) => {
                PublicKey::ECIESThreshold(key.get_public_key().clone())
            }
        }
    }

    pub fn get_app_id(&self) -> &u32 {
        match self {
            PrivateKeyShare::ECIESThreshold(key) => key.get_app_id(),
        }
    }
    pub fn pem(&self) -> Result<String, SchemeError> {
        let r = self.to_bytes();
        if let Ok(bytes) = r {
            let encoded_url = general_purpose::URL_SAFE.encode(bytes);
            return Ok(encoded_url);
        }
        Err(r.unwrap_err())
    }

    pub fn from_pem(pem: &str) -> Result<Self, SchemeError> {
        let r = general_purpose::URL_SAFE.decode(pem);
        if let Ok(bytes) = r {
            return PrivateKeyShare::from_bytes(&bytes);
        }

        Err(SchemeError::DeserializationFailed)
    }
}
struct PublicKeyVisitor;
impl<'de> serde::de::Visitor<'de> for PublicKeyVisitor {
    type Value = PublicKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a sequence of bytes")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut key_vec = Vec::new();
        while let Ok(Some(next)) = seq.next_element() {
            key_vec.push(next);
        }
        let key = PublicKey::from_bytes(&key_vec); //TODO: fix
        Ok(key.unwrap())
    }
}
#[derive(AsnType, Clone, PartialEq, Debug)]
#[rasn(enumerated)]
pub enum Verifier {
    ECIESThreshold(ECIESVerifier),
}
impl Eq for Verifier {}
impl Verifier {
    pub fn get_blind_shares(&self) -> &Share {
        match self {
            Verifier::ECIESThreshold(verifier) => verifier.get_blind_shares(),
        }
    }
    pub fn get_verifier_set(&self) -> &PedersenVerifier<Scalar, ProjectivePoint> {
        match self {
            Verifier::ECIESThreshold(verifier) => verifier.get_verifier(),
        }
    }
    pub fn get_blind_share_id(&self) -> u8 {
        match self {
            Verifier::ECIESThreshold(verifier) => verifier.get_blind_share_id(),
        }
    }

    pub fn pem(&self) -> Result<String, SchemeError> {
        let r = self.to_bytes();
        if let Ok(bytes) = r {
            let encoded_url = general_purpose::URL_SAFE.encode(bytes);
            return Ok(encoded_url);
        }
        Err(r.unwrap_err())
    }

    pub fn from_pem(pem: &str) -> Result<Self, SchemeError> {
        let r = general_purpose::URL_SAFE.decode(pem);
        if let Ok(bytes) = r {
            return Verifier::from_bytes(&bytes);
        }

        Err(SchemeError::DeserializationFailed)
    }
}
impl Serializable for Verifier {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        match self {
            Verifier::ECIESThreshold(verifier) => {
                let result = asn1::write(|w| {
                    w.write_element(&asn1::SequenceWriter::new(&|w| {
                        // 1. Write scheme ID
                        w.write_element(&ThresholdScheme::ECIESThreshold.get_id())?;

                        // 2. Serialize inner verifier
                        let verifier_bytes = verifier
                            .to_bytes() // ECIESVerifier must implement Serializable
                            .map_err(|_| WriteError::AllocationError)?;
                        w.write_element(&verifier_bytes.as_slice())?;

                        Ok(())
                    }))
                });

                result.map_err(|_| SchemeError::SerializationFailed)
            }
        }
    }
    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result = asn1::parse(bytes, |d| {
            d.read_element::<asn1::Sequence>()?.parse(|d| {
                let scheme = ThresholdScheme::from_id(d.read_element::<u8>()?);
                let inner_bytes = d.read_element::<&[u8]>()?.to_vec();

                match scheme {
                    Some(ThresholdScheme::ECIESThreshold) => {
                        let verifier = ECIESVerifier::from_bytes(&inner_bytes)
                            .map_err(|_| ParseError::new(asn1::ParseErrorKind::InvalidValue))?;
                        Ok(Verifier::ECIESThreshold(verifier))
                    }
                    _ => Err(ParseError::new(asn1::ParseErrorKind::InvalidValue)),
                }
            })
        });

        result.map_err(|_| SchemeError::DeserializationFailed)
    }
}
struct VerifierVisitor;
impl serde::Serialize for Verifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match Serializable::to_bytes(self) {
            Ok(bytes) => {
                let mut seq = serializer.serialize_seq(Some(bytes.len()))?;
                for byte in bytes.iter() {
                    seq.serialize_element(byte)?;
                }
                seq.end()
            }
            Err(err) => Err(serde::ser::Error::custom(format!(
                "Could not serialize Verifier: {:?}",
                err
            ))),
        }
    }
}
impl<'de> serde::de::Visitor<'de> for VerifierVisitor {
    type Value = Verifier;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("Verifier as ASN.1 byte sequence")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut bytes = Vec::new();
        while let Some(b) = seq.next_element()? {
            bytes.push(b);
        }

        Verifier::from_bytes(&bytes).map_err(|e| {
            serde::de::Error::custom(format!("Failed to deserialize Verifier: {:?}", e))
        })
    }
}

impl<'de> serde::Deserialize<'de> for Verifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(VerifierVisitor)
    }
}
