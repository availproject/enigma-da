use super::key_type::*;
use super::keys::{PrivateKeyShare, Verifier};
use crypto_bigint::rand_core::CryptoRngCore;
use k256::ProjectivePoint;
use k256::Scalar;
use proto::new_schemes::ThresholdScheme;
use vsss_rs_std::pedersen;
pub struct KeyGenerator {}

impl KeyGenerator {
    pub fn generate_keys(
        n: u8,
        t: u8,
        mut rng: &mut impl CryptoRngCore,
        scheme: &ThresholdScheme,
        app_id: u32,
    ) -> Result<(Vec<PrivateKeyShare>, Vec<Verifier>), Box<dyn std::error::Error>> {
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

                let publickey = ECIESPublicKey::new(n, t, public_key.clone(), app_id);
                let mut private_keys = Vec::new();
                let mut verification = Vec::new();
                for (i, (share, blind_share)) in shares.iter().zip(blind_shares.iter()).enumerate()
                {
                    private_keys.push(PrivateKeyShare::ECIESThreshold(ECIESPrivateKey::new(
                        (i + 1) as u8,
                        share.clone(),
                        &publickey,
                    )));
                    verification.push(Verifier::ECIESThreshold(ECIESVerifier::new(
                        (i + 1) as u8,
                        blind_share.clone(),
                        verifier.clone(), // likely needs Clone on PedersenVerifier
                    )));
                }

                Ok((private_keys, verification))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_pedersen_verifier_validates_shares() {
        let mut rng = OsRng;
        let n = 5u8;
        let t = 3u8;
        let scheme = ThresholdScheme::ECIESThreshold;
        let app_id: u32 = 1234;

        let (private_keys, verifiers) =
            KeyGenerator::generate_keys(n, t, &mut rng, &scheme, app_id)
                .expect("Failed to generate keys");

        assert_eq!(private_keys.len(), n as usize);
        assert_eq!(verifiers.len(), n as usize);

        for (priv_key, verifier) in private_keys.iter().zip(verifiers.iter()) {
            match (priv_key, verifier) {
                (PrivateKeyShare::ECIESThreshold(priv_key), Verifier::ECIESThreshold(verifier)) => {
                    let share = priv_key.get_share();
                    let blind = verifier.get_blind_shares();
                    let vset = verifier.get_verifier();

                    assert!(
                        vset.verify(share, blind).is_ok(),
                        "Verifier failed to verify the share"
                    );
                }
            }
        }
    }
}
