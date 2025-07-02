use crate::interface::{SchemeError, Serializable};
use asn1::ParseError;
use ecies::PublicKey;
use vsss_rs_std::Share;

#[derive(Clone, PartialEq, Debug)]
pub struct ECIESPublicKey {
    pub n: u8,
    pub k: u8,
    pub app_id: u32,
    pub pk: PublicKey,
}
impl ECIESPublicKey {
    pub fn get_n(&self) -> u8 {
        self.n
    }
    pub fn get_k(&self) -> u8 {
        self.k
    }
    pub fn get_app_id(&self) -> &u32 {
        &self.app_id
    }
    pub fn get_pk(&self) -> &PublicKey {
        &self.pk
    }

    pub fn new(n: u8, k: u8, pk: PublicKey, app_id: u32) -> Self {
        let k = Self { n, k, app_id, pk };
        k
    }
}
impl Serializable for ECIESPublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.n as u64))?;
                w.write_element(&(self.k as u64))?;
                let pk_bytes = self.pk.serialize();
                w.write_element(&pk_bytes.as_slice())?;
                let app_id_bytes = self.app_id.to_be_bytes();
                w.write_element(&app_id_bytes.as_slice())?;

                Ok(())
            }))
        });

        result.map_err(|_| SchemeError::SerializationFailed)
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            d.read_element::<asn1::Sequence>()?.parse(|d| {
                let n = d.read_element::<u64>()? as u8;
                let k = d.read_element::<u64>()? as u8;
                let pk_bytes = d.read_element::<&[u8]>()?;
                let app_id_bytes = d.read_element::<&[u8]>()?;
                let pk = if pk_bytes.len() == 33 {
                    // Compressed format
                    let pk_array: [u8; 33] = pk_bytes
                        .try_into()
                        .map_err(|_| ParseError::new(asn1::ParseErrorKind::ExtraData))?;
                    PublicKey::parse_compressed(&pk_array)
                        .map_err(|_| ParseError::new(asn1::ParseErrorKind::ExtraData))?
                } else if pk_bytes.len() == 65 {
                    // Uncompressed format
                    let pk_array: [u8; 65] = pk_bytes
                        .try_into()
                        .map_err(|_| ParseError::new(asn1::ParseErrorKind::ExtraData))?;
                    PublicKey::parse(&pk_array)
                        .map_err(|_| ParseError::new(asn1::ParseErrorKind::ExtraData))?
                } else {
                    // for other lengths
                    PublicKey::parse_slice(pk_bytes, None)
                        .map_err(|_| ParseError::new(asn1::ParseErrorKind::ExtraData))?
                };

                let app_id = u32::from_be_bytes(
                    app_id_bytes
                        .try_into()
                        .map_err(|_| ParseError::new(asn1::ParseErrorKind::ExtraData))?,
                );

                Ok(Self { n, k, app_id, pk })
            })
        });

        result.map_err(|_| SchemeError::DeserializationFailed)
    }
}
// pub fn decode_projective_point(b: &[u8]) -> Option<ProjectivePoint> {
//     let mut repr = <ProjectivePoint as GroupEncoding>::Repr::default();
//     AsMut::<[u8]>::as_mut(&mut repr).copy_from_slice(b);

//     ProjectivePoint::from_bytes(&repr).into()
// }

#[derive(Clone, Debug, PartialEq)]
pub struct ECIESPrivateKey {
    pub id: u8,
    pub xi: Share, // si_values[id]
    pub pubkey: ECIESPublicKey,
}

impl ECIESPrivateKey {
    pub fn get_share_id(&self) -> u8 {
        self.id
    }

    pub fn get_app_id(&self) -> &u32 {
        &self.pubkey.app_id
    }

    pub fn get_threshold(&self) -> u8 {
        self.pubkey.k
    }
    pub fn get_share(&self) -> &Share {
        &self.xi
    }
    pub fn get_public_key(&self) -> &ECIESPublicKey {
        &self.pubkey
    }

    pub fn new(id: u8, xi: Share, pubkey: &ECIESPublicKey) -> Self {
        Self {
            id: id.clone(),
            xi: xi.clone(),
            pubkey: pubkey.clone(),
        }
    }
}
impl Serializable for ECIESPrivateKey {
    fn to_bytes(&self) -> Result<Vec<u8>, SchemeError> {
        let result = asn1::write(|w| {
            w.write_element(&asn1::SequenceWriter::new(&|w| {
                w.write_element(&(self.id as u64))?;
                let xi_bytes: Vec<u8> = self.xi.clone().into();
                w.write_element(&xi_bytes.as_slice())?;
                let pubkey_bytes = self.pubkey.to_bytes().unwrap();

                w.write_element(&pubkey_bytes.as_slice())?;

                Ok(())
            }))
        });

        result.map_err(|_| SchemeError::SerializationFailed)
    }

    fn from_bytes(bytes: &Vec<u8>) -> Result<Self, SchemeError> {
        let result: asn1::ParseResult<_> = asn1::parse(bytes, |d| {
            d.read_element::<asn1::Sequence>()?.parse(|d| {
                let id = d.read_element::<u64>()? as u8;
                let xi_bytes = d.read_element::<&[u8]>()?;
                let pubkey_bytes = d.read_element::<&[u8]>()?;
                let xi = Share::try_from(xi_bytes)
                    .map_err(|_| ParseError::new(asn1::ParseErrorKind::InvalidValue))?;

                let pk = ECIESPublicKey::from_bytes(&pubkey_bytes.to_vec());
                let pubkey = pk.unwrap();

                Ok(Self { id, xi, pubkey })
            })
        });

        result.map_err(|_| SchemeError::DeserializationFailed)
    }
}
