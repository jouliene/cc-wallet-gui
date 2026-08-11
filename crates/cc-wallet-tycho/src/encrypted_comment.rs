use anyhow::{Context, Result, bail, ensure};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::VerifyingKey;
use zeroize::Zeroizing;

use crate::everwallet::{COMMENT_CELL_BYTES, MAX_COMMENT_BYTES};
use tycho_types::prelude::*;

pub const ENCRYPTED_COMMENT_OP: u32 = 0x4343_4531;

pub const ENCRYPTED_COMMENT_VERSION: u8 = 1;

pub const ENCRYPTED_PREFIX_BYTES: usize = 1 + 32;

pub const SEAL_OVERHEAD_BYTES: usize = 24 + 16;

pub const MAX_ENCRYPTED_COMMENT_BYTES: usize =
    MAX_COMMENT_BYTES - ENCRYPTED_PREFIX_BYTES - SEAL_OVERHEAD_BYTES;

const ROOT_BYTES: usize = 123 - ENCRYPTED_PREFIX_BYTES - 24;

const KEY_CONTEXT: &str = "cc-wallet 2026 encrypted comment v1";

pub fn shared_secret(
    my_scalar: &curve25519_dalek::Scalar,
    their_key: &VerifyingKey,
) -> Zeroizing<[u8; 32]> {
    let point: MontgomeryPoint = their_key.to_montgomery();
    let shared = point * my_scalar;
    Zeroizing::new(blake3::derive_key(KEY_CONTEXT, shared.as_bytes()))
}

pub fn comment_aad(sender: &str, recipient: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(sender.len() + 1 + recipient.len());
    aad.extend_from_slice(sender.as_bytes());
    aad.push(0);
    aad.extend_from_slice(recipient.as_bytes());
    aad
}

pub fn encrypted_comment_payload(sender_key: &[u8; 32], sealed: &[u8]) -> Result<Cell> {
    ensure!(
        sealed.len() >= 24 + 16,
        "a sealed comment carries at least its nonce and tag"
    );
    let body_len = ENCRYPTED_PREFIX_BYTES + sealed.len();
    ensure!(
        body_len <= MAX_COMMENT_BYTES,
        "an encrypted comment of {body_len} bytes exceeds the {MAX_COMMENT_BYTES}-byte budget"
    );

    let (nonce, ciphertext) = sealed.split_at(24);
    let (head, mut rest) = ciphertext.split_at(ciphertext.len().min(ROOT_BYTES));
    let mut tail: Vec<&[u8]> = Vec::new();
    while !rest.is_empty() {
        let (chunk, remainder) = rest.split_at(rest.len().min(COMMENT_CELL_BYTES));
        tail.push(chunk);
        rest = remainder;
    }

    let mut cell: Option<Cell> = None;
    for chunk in tail.iter().rev() {
        let mut builder = CellBuilder::new();
        builder.store_raw(chunk, (chunk.len() * 8) as u16)?;
        if let Some(next) = cell.take() {
            builder.store_reference(next)?;
        }
        cell = Some(builder.build()?);
    }

    let mut root = CellBuilder::new();
    root.store_u32(ENCRYPTED_COMMENT_OP)?;
    root.store_u8(ENCRYPTED_COMMENT_VERSION)?;
    root.store_raw(sender_key, 256)?;
    root.store_raw(nonce, 192)?;
    root.store_raw(head, (head.len() * 8) as u16)?;
    if let Some(next) = cell {
        root.store_reference(next)?;
    }
    root.build()
        .context("failed to build the encrypted comment payload")
}

pub struct EncryptedComment {
    pub sender_key: [u8; 32],
    pub sealed: Vec<u8>,
}

pub fn parse_encrypted_comment(body: &Cell) -> Result<Option<EncryptedComment>> {
    let Ok(mut slice) = body.as_slice() else {
        return Ok(None);
    };
    if slice.size_bits() < 32 || slice.load_u32()? != ENCRYPTED_COMMENT_OP {
        return Ok(None);
    }
    let version = slice.load_u8()?;
    if version != ENCRYPTED_COMMENT_VERSION {
        bail!("this comment was written by a newer wallet (format version {version})");
    }
    let mut sender_key = [0u8; 32];
    slice.load_raw(&mut sender_key, 256)?;
    let mut sealed = vec![0u8; 24];
    slice.load_raw(&mut sealed, 192)?;

    let mut cell = body.clone();
    loop {
        let mut part = cell.as_slice()?;
        if std::ptr::eq(cell.as_ref(), body.as_ref()) {
            part.skip_first(32 + 8 + 256 + 192, 0)?;
        }
        let bits = part.size_bits() as usize;
        ensure!(
            bits.is_multiple_of(8),
            "an encrypted comment is a whole number of bytes"
        );
        let mut chunk = vec![0u8; bits / 8];
        part.load_raw(&mut chunk, bits as u16)?;
        sealed.extend_from_slice(&chunk);
        match cell.reference_cloned(0) {
            Some(next) => cell = next,
            None => break,
        }
    }
    ensure!(
        sealed.len() >= 24 + 16,
        "an encrypted comment carries at least its nonce and tag"
    );
    Ok(Some(EncryptedComment { sender_key, sealed }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    fn keys(seed: u8) -> KeyPair {
        KeyPair::from_secret_bytes([seed; 32])
    }

    #[test]
    fn both_ends_arrive_at_the_same_secret_from_opposite_sides() {
        let alice = keys(1);
        let bob = keys(2);

        let from_alice = alice.comment_secret(bob.public_key());
        let from_bob = bob.comment_secret(alice.public_key());

        assert_eq!(
            from_alice.as_ref(),
            from_bob.as_ref(),
            "the sender must reach the same key as the recipient, or cannot read back what it sent"
        );

        let stranger = keys(3);
        assert_ne!(
            from_alice.as_ref(),
            alice.comment_secret(stranger.public_key()).as_ref(),
            "a different counterparty is a different conversation"
        );
    }

    #[test]
    fn a_sealed_comment_survives_the_trip_through_a_cell() {
        let sender = keys(1).public_key_bytes();
        let sealed: Vec<u8> = (0u8..=255).cycle().take(24 + 300 + 16).collect();

        let cell = encrypted_comment_payload(&sender, &sealed).expect("the payload builds");
        let read = parse_encrypted_comment(&cell)
            .expect("the payload parses")
            .expect("it is an encrypted comment");

        assert_eq!(read.sender_key, sender);
        assert_eq!(read.sealed, sealed, "every byte comes back, snake and all");
    }

    #[test]
    fn a_short_one_needs_no_second_cell_and_a_long_one_chains() {
        let sender = keys(1).public_key_bytes();

        let short = encrypted_comment_payload(&sender, &[7u8; 24 + 16]).unwrap();
        assert_eq!(short.reference_count(), 0);

        let long = encrypted_comment_payload(&sender, &[7u8; 24 + ROOT_BYTES + 1 + 16]).unwrap();
        assert_eq!(long.reference_count(), 1);
    }

    #[test]
    fn a_plain_comment_is_not_mistaken_for_an_encrypted_one() {
        let plain = crate::everwallet::comment_payload("rent for July").unwrap();

        assert!(
            parse_encrypted_comment(&plain).unwrap().is_none(),
            "a comment in the clear reads as what it is"
        );
    }

    #[test]
    fn a_comment_of_exactly_the_budget_still_fits() {
        assert_eq!(
            MAX_ENCRYPTED_COMMENT_BYTES,
            MAX_COMMENT_BYTES - 73,
            "version, key, nonce and tag are paid for out of the same budget"
        );

        let sender = keys(1).public_key_bytes();
        let exact = vec![0u8; 24 + MAX_ENCRYPTED_COMMENT_BYTES + 16];
        let cell = encrypted_comment_payload(&sender, &exact)
            .expect("a comment cut to the budget is a comment that fits");
        let read = parse_encrypted_comment(&cell).unwrap().unwrap();
        assert_eq!(read.sealed.len(), exact.len());

        let one_over = vec![0u8; 24 + MAX_ENCRYPTED_COMMENT_BYTES + 1 + 16];
        assert!(
            encrypted_comment_payload(&sender, &one_over).is_err(),
            "and one byte past it is not"
        );
    }
}
