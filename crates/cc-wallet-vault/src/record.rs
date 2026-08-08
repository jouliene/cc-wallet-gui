use zeroize::Zeroizing;

use crate::aead::{NONCE_LEN, TAG_LEN, open, seal};
use crate::error::{VaultError, VaultResult};

pub const RECORD_SEAL_OVERHEAD: usize = NONCE_LEN + TAG_LEN;

pub fn seal_record(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> VaultResult<Vec<u8>> {
    seal(key, plaintext, aad)
}

pub fn open_record(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> VaultResult<Zeroizing<Vec<u8>>> {
    open(
        key,
        blob,
        aad,
        VaultError::Corrupt("this record was not written by this wallet"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];
    const AAD: &[u8] = b"0:aabb\x00\x00\x00\x01";
    const PLAIN: &[u8] = b"\x00\x0bInna's phone86594423664";

    #[test]
    fn a_record_round_trips_under_its_own_key_and_aad() {
        let blob = seal_record(&KEY, AAD, PLAIN).unwrap();

        assert_eq!(blob.len(), PLAIN.len() + RECORD_SEAL_OVERHEAD);
        assert!(
            !blob.windows(PLAIN.len()).any(|w| w == PLAIN),
            "the plaintext does not appear in what goes on chain"
        );
        assert_eq!(&open_record(&KEY, AAD, &blob).unwrap()[..], PLAIN);
    }

    #[test]
    fn every_sealing_uses_a_fresh_nonce() {
        let first = seal_record(&KEY, AAD, PLAIN).unwrap();
        let second = seal_record(&KEY, AAD, PLAIN).unwrap();

        assert_ne!(
            first, second,
            "the same record sealed twice never produces the same bytes"
        );
        assert_eq!(&open_record(&KEY, AAD, &first).unwrap()[..], PLAIN);
        assert_eq!(&open_record(&KEY, AAD, &second).unwrap()[..], PLAIN);
    }

    #[test]
    fn a_record_cannot_be_replayed_into_another_slot_or_wallet() {
        let blob = seal_record(&KEY, AAD, PLAIN).unwrap();

        let other_slot = b"0:aabb\x00\x00\x00\x02";
        assert!(
            open_record(&KEY, other_slot, &blob).is_err(),
            "the aad binds a record to its own number"
        );

        let other_owner = b"0:ccdd\x00\x00\x00\x01";
        assert!(
            open_record(&KEY, other_owner, &blob).is_err(),
            "the aad binds a record to its own owner"
        );

        let other_key = [9u8; 32];
        assert!(
            open_record(&other_key, AAD, &blob).is_err(),
            "another wallet's key does not open it"
        );
    }

    #[test]
    fn a_tampered_or_truncated_blob_is_refused_rather_than_guessed_at() {
        let mut blob = seal_record(&KEY, AAD, PLAIN).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(open_record(&KEY, AAD, &blob).is_err());

        assert!(matches!(
            open_record(&KEY, AAD, &[0u8; RECORD_SEAL_OVERHEAD - 1]),
            Err(VaultError::Truncated)
        ));
        assert!(matches!(
            open_record(&KEY, AAD, &[]),
            Err(VaultError::Truncated)
        ));
    }
}
