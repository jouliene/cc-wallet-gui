use zeroize::Zeroizing;

use crate::aead;
use crate::error::{VaultError, VaultResult};
use crate::params::{KdfParams, derive_kek};
use crate::{FORMAT_VERSION, MAGIC};

const KDF_ID_ARGON2ID: u8 = 1;
const AEAD_ID_XCHACHA: u8 = 1;

const PREFIX_LEN: usize = 40;
pub(crate) const KEYSLOT_LEN: usize = PREFIX_LEN + aead::NONCE_LEN + 32 + aead::TAG_LEN;

fn encode_prefix(params: KdfParams, salt: &[u8; 16]) -> [u8; PREFIX_LEN] {
    let mut out = [0u8; PREFIX_LEN];
    out[0..8].copy_from_slice(&MAGIC);
    out[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    out[10] = KDF_ID_ARGON2ID;
    out[11..15].copy_from_slice(&params.m_kib.to_le_bytes());
    out[15..19].copy_from_slice(&params.t.to_le_bytes());
    out[19..23].copy_from_slice(&params.p.to_le_bytes());
    out[23..39].copy_from_slice(salt);
    out[39] = AEAD_ID_XCHACHA;
    out
}

pub(crate) fn build(
    password: &[u8],
    params: KdfParams,
    salt: &[u8; 16],
    dek: &[u8; 32],
) -> VaultResult<Vec<u8>> {
    let prefix = encode_prefix(params, salt);
    let kek = derive_kek(password, salt, params)?;
    let wrap = aead::seal(&kek, dek, &prefix)?;
    let mut out = Vec::with_capacity(KEYSLOT_LEN);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(&wrap);
    debug_assert_eq!(out.len(), KEYSLOT_LEN);
    Ok(out)
}

pub(crate) struct Opened {
    pub params: KdfParams,
    pub dek: Zeroizing<[u8; 32]>,
}

pub(crate) fn validate_header(bytes: &[u8]) -> VaultResult<KdfParams> {
    if bytes.len() < KEYSLOT_LEN {
        return Err(VaultError::Truncated);
    }
    if bytes[0..8] != MAGIC {
        return Err(VaultError::UnsupportedFormat("not a cc-wallet vault"));
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != FORMAT_VERSION {
        return Err(VaultError::UnsupportedFormat(if version < FORMAT_VERSION {
            "vault was created by an older version of CC Wallet"
        } else {
            "vault was created by a newer version of CC Wallet"
        }));
    }
    if bytes[10] != KDF_ID_ARGON2ID {
        return Err(VaultError::UnsupportedFormat("unknown KDF id"));
    }
    let params = KdfParams {
        m_kib: u32::from_le_bytes([bytes[11], bytes[12], bytes[13], bytes[14]]),
        t: u32::from_le_bytes([bytes[15], bytes[16], bytes[17], bytes[18]]),
        p: u32::from_le_bytes([bytes[19], bytes[20], bytes[21], bytes[22]]),
    };
    params.validate()?;
    if bytes[39] != AEAD_ID_XCHACHA {
        return Err(VaultError::UnsupportedFormat("unknown AEAD id"));
    }
    Ok(params)
}

pub(crate) fn open(bytes: &[u8], password: &[u8]) -> VaultResult<Opened> {
    let params = validate_header(bytes)?;
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&bytes[23..39]);

    let prefix = &bytes[..PREFIX_LEN];
    let wrap = &bytes[PREFIX_LEN..KEYSLOT_LEN];
    let kek = derive_kek(password, &salt, params)?;
    let dek_bytes = aead::open(&kek, wrap, prefix, VaultError::WrongPassword)?;

    let mut dek = Zeroizing::new([0u8; 32]);
    dek.copy_from_slice(&dek_bytes);
    Ok(Opened { params, dek })
}
