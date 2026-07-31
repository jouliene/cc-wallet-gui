use cc_wallet_domain::{RecordId, RiskNonce};

trait SecureRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error>;
}

struct OperatingSystemRandom;

impl SecureRandom for OperatingSystemRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error> {
        getrandom::fill(destination)
    }
}

fn random_bytes(random: &impl SecureRandom) -> Result<[u8; 32], getrandom::Error> {
    let mut bytes = [0u8; 32];
    random.fill(&mut bytes)?;
    Ok(bytes)
}

pub(crate) fn new_record_id() -> Result<RecordId, getrandom::Error> {
    random_bytes(&OperatingSystemRandom).map(RecordId::from_bytes)
}

pub(crate) fn new_risk_nonce() -> Result<RiskNonce, getrandom::Error> {
    random_bytes(&OperatingSystemRandom).map(RiskNonce::from_bytes)
}

pub(crate) fn new_auth_nonce() -> Result<u64, getrandom::Error> {
    let bytes = random_bytes(&OperatingSystemRandom)?;
    Ok(u64::from_le_bytes(bytes[..8].try_into().expect(
        "the authorization nonce prefix is exactly eight bytes",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRandom(u8);

    impl SecureRandom for FixedRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<(), getrandom::Error> {
            destination.fill(self.0);
            Ok(())
        }
    }

    struct FailingRandom;

    impl SecureRandom for FailingRandom {
        fn fill(&self, _destination: &mut [u8]) -> Result<(), getrandom::Error> {
            Err(getrandom::Error::UNEXPECTED)
        }
    }

    #[test]
    fn complete_random_bytes_become_the_exact_identifier() {
        assert_eq!(random_bytes(&FixedRandom(0xa5)).unwrap(), [0xa5; 32]);
    }

    #[test]
    fn rng_failure_returns_no_default_or_partial_identifier() {
        assert_eq!(
            random_bytes(&FailingRandom).unwrap_err(),
            getrandom::Error::UNEXPECTED
        );
    }

    #[test]
    fn production_record_and_nonce_creation_are_fallible() {
        let record = new_record_id().unwrap();
        let nonce = new_risk_nonce().unwrap();
        let _auth_nonce = new_auth_nonce().unwrap();
        assert_eq!(record.as_bytes().len(), 32);
        assert_eq!(nonce.as_bytes().len(), 32);
    }
}
