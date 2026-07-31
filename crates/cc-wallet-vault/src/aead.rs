use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{VaultError, VaultResult};

pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const TAG_LEN: usize = 16;

fn random_nonce() -> VaultResult<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| VaultError::Rng)?;
    Ok(nonce)
}

fn cipher(key: &[u8; 32]) -> VaultResult<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key).map_err(|_| VaultError::Crypto("bad key length"))
}

pub(crate) fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> VaultResult<Vec<u8>> {
    let nonce = random_nonce()?;
    let ct = cipher(key)?
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::Crypto("AEAD encryption failed"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub(crate) fn open(
    key: &[u8; 32],
    blob: &[u8],
    aad: &[u8],
    on_tag_fail: VaultError,
) -> VaultResult<Zeroizing<Vec<u8>>> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(VaultError::Truncated);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let nonce = XNonce::try_from(nonce).map_err(|_| VaultError::Crypto("bad nonce length"))?;
    let pt = cipher(key)?
        .decrypt(&nonce, Payload { msg: ct, aad })
        .map_err(|_| on_tag_fail)?;
    Ok(Zeroizing::new(pt))
}
