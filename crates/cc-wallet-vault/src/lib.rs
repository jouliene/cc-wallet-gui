mod aead;
pub mod error;
mod keyslot;
pub mod params;
mod vault;

pub(crate) const MAGIC: [u8; 8] = *b"CCWALLET";
pub(crate) const FORMAT_VERSION: u16 = 1;

pub use error::{VaultError, VaultResult};
pub use params::KdfParams;
pub use vault::{
    ActivitySection, MAX_DISPLAY_NAME_BYTES, MAX_HEADER_PROBE_LEN, OpenedContainer, OpenedKeyslot,
    Purpose, Vault, container_declared_len, keyslot_prefix, looks_like_container,
    read_display_name, read_kdf_params, read_save_counter,
};

#[cfg(debug_assertions)]
pub fn kdf_invocations() -> u64 {
    params::KDF_INVOCATIONS.with(std::cell::Cell::get)
}

#[cfg(debug_assertions)]
pub fn reset_kdf_invocations() {
    params::KDF_INVOCATIONS.with(|count| count.set(0));
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHEAP: KdfParams = KdfParams {
        m_kib: 32,
        t: 2,
        p: 1,
    };
    const PW: &[u8] = b"correct horse battery staple";
    const WALLET: &[u8] = b"{\"seed\":\"one two three\",\"endpoint\":\"http://x\"}";
    const JOURNAL: &[u8] = b"{\"records\":[]}";
    const HISTORY: &[u8] = b"[{\"lt\":42,\"amount\":1000}]";

    fn new_vault() -> Vault {
        Vault::create_with(PW, CHEAP).unwrap()
    }

    fn seal_all(v: &Vault, counter: u64) -> Vec<u8> {
        v.seal_container(
            counter,
            &[
                (Purpose::Wallet, WALLET),
                (Purpose::Activity, HISTORY),
                (Purpose::Journal, JOURNAL),
            ],
        )
        .unwrap()
    }

    #[test]
    fn container_round_trips_wallet_journal_and_activity() {
        let file = seal_all(&new_vault(), 3);
        let opened = Vault::open_container(&file, PW).unwrap();
        assert_eq!(&opened.wallet[..], WALLET);
        assert_eq!(&opened.journal[..], JOURNAL);
        assert_eq!(opened.save_counter, 3);
        assert!(matches!(&opened.activity, ActivitySection::Present(a) if &a[..] == HISTORY));
    }

    #[test]
    fn wrong_password_comes_only_from_the_keyslot() {
        let file = seal_all(&new_vault(), 1);
        assert!(matches!(
            Vault::open_container(&file, b"wrong"),
            Err(VaultError::WrongPassword)
        ));
    }

    #[test]
    fn kdf_parameter_downgrade_is_blocked() {
        let file = seal_all(&new_vault(), 1);
        let mut tampered = file.clone();
        tampered[11..15].copy_from_slice(&16u32.to_le_bytes());
        assert!(matches!(
            Vault::open_container(&tampered, PW),
            Err(VaultError::WrongPassword)
        ));
        let mut bomb = file;
        bomb[11..15].copy_from_slice(&16_777_216u32.to_le_bytes());
        assert!(matches!(
            Vault::open_container(&bomb, PW),
            Err(VaultError::ParamsRejected(_))
        ));
    }

    #[test]
    fn truncated_and_bad_magic_are_rejected() {
        let file = seal_all(&new_vault(), 1);
        assert!(matches!(
            Vault::open_container(&file[..50], PW),
            Err(VaultError::Truncated)
        ));
        let mut bad = file.clone();
        bad[0] = b'X';
        assert!(matches!(
            Vault::open_container(&bad, PW),
            Err(VaultError::UnsupportedFormat(_))
        ));
    }

    #[test]
    fn a_re_keyed_vault_does_not_open_old_containers() {
        let old_file = seal_all(&new_vault(), 1);
        let new = Vault::create_with(b"a different password", CHEAP).unwrap();
        let new_file = seal_all(&new, 1);
        assert!(Vault::open_container(&new_file, b"a different password").is_ok());
        assert!(matches!(
            Vault::open_container(&new_file, PW),
            Err(VaultError::WrongPassword)
        ));
        assert!(matches!(
            Vault::open_container(&old_file, b"a different password"),
            Err(VaultError::WrongPassword)
        ));
    }

    #[test]
    fn kdf_params_are_preserved_across_open() {
        let file = seal_all(&new_vault(), 1);
        let opened = Vault::open_container(&file, PW).unwrap();
        assert_eq!(opened.vault.kdf_params(), CHEAP);
    }

    #[test]
    fn read_save_counter_matches_the_sealed_counter() {
        let file = seal_all(&new_vault(), 99);
        assert_eq!(read_save_counter(&file).unwrap(), 99);
    }
}
