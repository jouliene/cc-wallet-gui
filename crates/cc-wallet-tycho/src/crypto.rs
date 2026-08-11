use core::fmt;

use bip32::{DerivationPath, XPrv};
use bip39::Mnemonic;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub type SecretKeyBytes = [u8; 32];
pub type PublicKeyBytes = [u8; 32];
pub type SignatureBytes = [u8; 64];
pub type Result<T> = core::result::Result<T, CryptoError>;

pub const DEFAULT_DERIVATION_PURPOSE: u32 = 44;
pub const DEFAULT_DERIVATION_COIN_TYPE: u32 = 396;
pub const DEFAULT_DERIVATION_ACCOUNT: u32 = 0;
pub const DEFAULT_DERIVATION_CHANGE: u32 = 0;

#[derive(Debug)]
pub enum CryptoError {
    InvalidSecretLength { actual: usize },
    InvalidSecretHex(hex::FromHexError),
    InvalidPublicHex(hex::FromHexError),
    InvalidSignatureHex(hex::FromHexError),
    InvalidPublicKey(ed25519_dalek::SignatureError),
    InvalidSeedPhrase(bip39::Error),
    EntropyUnavailable(rand_core::Error),
    DerivationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretLength { actual } => {
                write!(f, "secret key must be 32 bytes, got {actual}")
            }
            Self::InvalidSecretHex(_) => f.write_str("secret key must be 64 hex chars"),
            Self::InvalidPublicHex(_) => f.write_str("public key must be 64 hex chars"),
            Self::InvalidSignatureHex(_) => f.write_str("signature must be 128 hex chars"),
            Self::InvalidPublicKey(_) => f.write_str("invalid ed25519 public key"),
            Self::InvalidSeedPhrase(_) => f.write_str("invalid seed phrase"),
            Self::EntropyUnavailable(_) => f.write_str("operating-system entropy is unavailable"),
            Self::DerivationFailed => f.write_str("failed to derive key from seed phrase"),
        }
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidSecretHex(error)
            | Self::InvalidPublicHex(error)
            | Self::InvalidSignatureHex(error) => Some(error),
            Self::InvalidPublicKey(_) => None,
            Self::InvalidSeedPhrase(error) => Some(error),
            Self::EntropyUnavailable(error) => Some(error),
            Self::InvalidSecretLength { .. } => None,
            Self::DerivationFailed => None,
        }
    }
}

pub struct Seed {
    phrase: Zeroizing<String>,
}

impl PartialEq for Seed {
    fn eq(&self, other: &Self) -> bool {
        self.phrase.as_bytes().ct_eq(other.phrase.as_bytes()).into()
    }
}
impl Eq for Seed {}

impl Seed {
    pub fn generate() -> Result<Self> {
        Self::generate_with_words(12)
    }

    pub fn generate_with_words(word_count: usize) -> Result<Self> {
        let entropy_len = match word_count {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => {
                return Err(CryptoError::InvalidSeedPhrase(bip39::Error::BadWordCount(
                    word_count,
                )));
            }
        };
        let mut entropy = Zeroizing::new([0u8; 32]);
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut entropy[..entropy_len])
            .map_err(CryptoError::EntropyUnavailable)?;
        let mnemonic = Mnemonic::from_entropy(&entropy[..entropy_len])
            .map_err(CryptoError::InvalidSeedPhrase)?;
        Ok(Self {
            phrase: Zeroizing::new(mnemonic.to_string()),
        })
    }

    pub fn parse(phrase: &str) -> Result<Self> {
        let phrase = phrase.trim();
        phrase
            .parse::<Mnemonic>()
            .map_err(CryptoError::InvalidSeedPhrase)?;
        Ok(Self {
            phrase: Zeroizing::new(phrase.to_owned()),
        })
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        &self.phrase
    }

    pub fn into_zeroizing(self) -> Zeroizing<String> {
        self.phrase
    }
}

impl AsRef<str> for Seed {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Seed").field(&"<redacted>").finish()
    }
}

#[repr(transparent)]
pub struct KeyPair {
    secret: SigningKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        Self {
            secret: SigningKey::generate(&mut rng),
        }
    }

    #[inline]
    pub fn from_secret_bytes(bytes: SecretKeyBytes) -> Self {
        let bytes = Zeroizing::new(bytes);
        Self::from_secret_ref(&bytes)
    }

    #[inline]
    fn from_secret_ref(bytes: &SecretKeyBytes) -> Self {
        Self {
            secret: SigningKey::from_bytes(bytes),
        }
    }

    #[inline]
    pub fn from_secret_slice(bytes: &[u8]) -> Result<Self> {
        let bytes: &SecretKeyBytes =
            bytes
                .try_into()
                .map_err(|_| CryptoError::InvalidSecretLength {
                    actual: bytes.len(),
                })?;
        Ok(Self::from_secret_ref(bytes))
    }

    pub fn from_secret_hex(secret_hex: &str) -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(secret_hex.trim(), &mut *bytes)
            .map_err(CryptoError::InvalidSecretHex)?;
        Ok(Self::from_secret_ref(&bytes))
    }

    pub fn from_seed(seed: &str) -> Result<Self> {
        Self::from_seed_with_index(seed, 0)
    }

    pub fn from_seed_with_index(seed: &str, index: u32) -> Result<Self> {
        Self::from_seed_with_path(seed, &derivation_path(index))
    }

    pub fn from_seed_with_path(seed: &str, path: &str) -> Result<Self> {
        let mnemonic: Mnemonic = seed
            .trim()
            .parse()
            .map_err(CryptoError::InvalidSeedPhrase)?;
        let seed = Zeroizing::new(mnemonic.to_seed(""));
        let path: DerivationPath = path.parse().map_err(|_| CryptoError::DerivationFailed)?;
        let xprv = XPrv::derive_from_path(seed.as_ref(), &path)
            .map_err(|_| CryptoError::DerivationFailed)?;
        let xprv_bytes = Zeroizing::new(xprv.to_bytes());
        Ok(Self::from_secret_ref(&xprv_bytes))
    }

    #[inline]
    pub(crate) fn secret_key(&self) -> &SigningKey {
        &self.secret
    }

    #[inline]
    pub fn public_key(&self) -> &VerifyingKey {
        self.secret.as_ref()
    }

    #[cfg(test)]
    #[inline]
    pub fn secret_key_bytes(&self) -> SecretKeyBytes {
        self.secret.to_bytes()
    }

    #[inline]
    pub fn public_key_bytes(&self) -> PublicKeyBytes {
        self.public_key().to_bytes()
    }

    /// The key this wallet and one other arrive at independently. Both sides
    /// compute it from their own scalar and the other's published key, which is
    /// what lets the sender read back what they sent.
    ///
    /// It reuses the signing key, because a wallet publishes no other: the
    /// recipient's account carries the key it signs with and nothing else.
    /// The same agreement from a key as it appears on chain — raw bytes out of
    /// an account — so callers need no signature types of their own.
    pub fn comment_secret_for(&self, their_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        let their_key =
            VerifyingKey::from_bytes(their_key).map_err(CryptoError::InvalidPublicKey)?;
        Ok(self.comment_secret(&their_key))
    }

    pub fn comment_secret(&self, their_key: &VerifyingKey) -> Zeroizing<[u8; 32]> {
        crate::encrypted_comment::shared_secret(&self.secret.to_scalar(), their_key)
    }

    pub fn derive_secret(&self, context: &str) -> Zeroizing<[u8; 32]> {
        let seed = Zeroizing::new(self.secret.to_bytes());
        Zeroizing::new(blake3::derive_key(context, seed.as_ref()))
    }

    #[cfg(test)]
    pub fn secret_key_hex(&self) -> String {
        hex::encode(self.secret_key_bytes())
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    #[inline]
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.secret.sign(data)
    }

    #[inline]
    pub fn sign_bytes(&self, data: &[u8]) -> SignatureBytes {
        self.sign(data).to_bytes()
    }

    #[inline]
    pub fn verify(&self, data: &[u8], signature: &Signature) -> bool {
        self.public_key().verify(data, signature).is_ok()
    }

    #[inline]
    pub fn verify_bytes(&self, data: &[u8], signature: &SignatureBytes) -> bool {
        self.verify(data, &Signature::from_bytes(signature))
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &self.public_key_hex())
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

pub fn derivation_path(index: u32) -> String {
    format!(
        "m/{DEFAULT_DERIVATION_PURPOSE}'/{DEFAULT_DERIVATION_COIN_TYPE}'/{DEFAULT_DERIVATION_ACCOUNT}'/{DEFAULT_DERIVATION_CHANGE}/{index}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn seed_partial_eq_still_correct() {
        const A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        const B: &str =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        assert!(Seed::parse(A).unwrap() == Seed::parse(A).unwrap());
        assert!(Seed::parse(A).unwrap() != Seed::parse(B).unwrap());
    }

    #[test]
    fn keypair_has_no_duplicate_public_key_storage() {
        assert_eq!(
            std::mem::size_of::<KeyPair>(),
            std::mem::size_of::<SigningKey>()
        );
    }

    #[test]
    fn bip39_mnemonic_wipes_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Mnemonic>();
    }

    #[test]
    fn secret_hex_roundtrip_derives_public_key() -> Result<()> {
        let keys = KeyPair::from_secret_hex(TEST_SECRET_HEX)?;

        assert_eq!(keys.secret_key_hex(), TEST_SECRET_HEX);
        assert_eq!(keys.public_key_bytes().len(), 32);
        let mut parsed = [0u8; 32];
        hex::decode_to_slice(keys.public_key_hex(), &mut parsed)
            .expect("the public key prints as 32 bytes of hex");
        assert_eq!(
            VerifyingKey::from_bytes(&parsed).expect("the printed key parses back"),
            *keys.public_key()
        );
        Ok(())
    }

    #[test]
    fn signs_and_verifies_messages() -> Result<()> {
        let keys = KeyPair::from_secret_hex(TEST_SECRET_HEX)?;
        let message = b"hello tycho";
        let signature = keys.sign(message);
        let signature_bytes = keys.sign_bytes(message);

        assert!(keys.verify(message, &signature));
        assert!(keys.verify_bytes(message, &signature_bytes));
        assert!(!keys.verify(b"tampered", &signature));
        Ok(())
    }

    #[test]
    fn parsers_fail_cleanly() {
        assert!(matches!(
            KeyPair::from_secret_slice(&[1, 2, 3]),
            Err(CryptoError::InvalidSecretLength { actual: 3 })
        ));
        assert!(KeyPair::from_secret_hex("abc").is_err());
    }

    #[test]
    fn a_derived_secret_is_stable_separated_by_context_and_is_not_the_signing_key() -> Result<()> {
        let keys = KeyPair::from_secret_hex(TEST_SECRET_HEX)?;
        let other = KeyPair::from_secret_hex(
            "0f0e0d0c0b0a09080706050403020100000102030405060708090a0b0c0d0e0f",
        )?;

        let first = keys.derive_secret("cc-wallet storage record key v1");
        assert_eq!(
            *first,
            *keys.derive_secret("cc-wallet storage record key v1"),
            "the same key and context always derive the same secret"
        );
        assert_ne!(
            *first,
            *keys.derive_secret("cc-wallet some other purpose v1"),
            "a different purpose derives an unrelated secret"
        );
        assert_ne!(
            *first,
            *other.derive_secret("cc-wallet storage record key v1"),
            "a different wallet derives an unrelated secret"
        );
        assert_ne!(
            *first,
            keys.secret_key_bytes(),
            "the derived secret is not the signing key itself"
        );
        Ok(())
    }

    #[test]
    fn debug_redacts_secret() -> Result<()> {
        let keys = KeyPair::from_secret_hex(TEST_SECRET_HEX)?;
        let debug = format!("{keys:?}");

        assert!(debug.contains(&keys.public_key_hex()));
        assert!(!debug.contains(TEST_SECRET_HEX));
        Ok(())
    }

    mod mnemonic {
        use super::*;

        const TEST_SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        #[test]
        fn key_derivation_pins_the_slip44_path_and_a_golden_public_key() -> Result<()> {
            let seed = Seed::parse(TEST_SEED)?;
            let first = KeyPair::from_seed(seed.as_str())?;
            let again = KeyPair::from_seed_with_path(TEST_SEED, &derivation_path(0))?;
            let second = KeyPair::from_seed_with_index(TEST_SEED, 1)?;

            assert_eq!(
                first.public_key_hex(),
                "77c647c114a311fc70d8f6d52d6ffef1ee105e36eba5a8769e3ce4d1a25bde25"
            );
            assert_eq!(first.public_key_hex(), again.public_key_hex());
            assert_ne!(first.public_key_hex(), second.public_key_hex());
            assert_eq!(derivation_path(7), "m/44'/396'/0'/0/7");
            Ok(())
        }

        #[test]
        fn seed_debug_redacts_phrase() -> Result<()> {
            let seed = Seed::parse(TEST_SEED)?;

            assert!(!format!("{seed:?}").contains("abandon"));
            assert_eq!(seed.as_str(), TEST_SEED);
            Ok(())
        }

        #[test]
        fn generated_seed_uses_every_approved_bip39_word_count() -> Result<()> {
            for word_count in [12, 15, 18, 21, 24] {
                let seed = Seed::generate_with_words(word_count)?;

                assert_eq!(seed.as_str().split_whitespace().count(), word_count);
                Seed::parse(seed.as_str())?;
            }
            Ok(())
        }

        #[test]
        fn generated_seed_rejects_an_unapproved_word_count_before_rng_use() {
            assert!(matches!(
                Seed::generate_with_words(11),
                Err(CryptoError::InvalidSeedPhrase(bip39::Error::BadWordCount(
                    11
                )))
            ));
        }
    }
}
