use super::key_type::*;
use super::keys::PrivateKeyShare;
use crypto_bigint::rand_core::CryptoRngCore;
use k256::ProjectivePoint;
use k256::Scalar;
use theta_proto::new_schemes::ThresholdScheme;
use vsss_rs_std::pedersen;
pub struct KeyGenerator {}

impl KeyGenerator {
    pub fn generate_keys(
        n: u8,
        t: u8,
        mut rng: &mut impl CryptoRngCore,
        scheme: &ThresholdScheme,
    ) -> Result<Vec<PrivateKeyShare>, Box<dyn std::error::Error>> {
        match scheme {
            ThresholdScheme::ECIESThreshold => {
                let (secret_key, public_key) = ecies::utils::generate_keypair();

                let sk_bytes = secret_key.serialize();
                let sk = k256::SecretKey::from_slice(&sk_bytes)
                    .expect("Failed to create secret key from bytes");
                let scalar = *sk.to_nonzero_scalar();
                let res = pedersen::split_secret::<Scalar, ProjectivePoint, _>(
                    t as usize, // threshold
                    n as usize, // total shares
                    scalar, None, // randomness
                    None, // g
                    None, // h
                    &mut rng,
                );

                assert!(res.is_ok(), "split_secret failed");
                let result = res.unwrap();
                let shares = result.secret_shares;
                let blind_shares = result.blind_shares;
                let verifier = result.verifier;
                for (s, b) in shares.iter().zip(blind_shares.iter()) {
                    assert!(verifier.verify(s, b).is_ok(), "share verification failed");
                }

                let publickey = ECIESPublicKey::new(n, t, public_key.clone());
                let mut private_keys = Vec::new();
                for (i, share) in shares.iter().enumerate() {
                    private_keys.push(PrivateKeyShare::ECIESThreshold(ECIESPrivateKey::new(
                        (i + 1) as u8,
                        share.clone(),
                        &publickey,
                    )));
                }

                Ok(private_keys)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_pedersen_secret_sharing() {
        let mut rng = OsRng;
        let n = 5u8;
        let t = 3u8;
        let scheme = ThresholdScheme::ECIESThreshold;

        let keys =
            KeyGenerator::generate_keys(n, t, &mut rng, &scheme).expect("Failed to generate keys");

        assert_eq!(keys.len(), n as usize);
    }
}
