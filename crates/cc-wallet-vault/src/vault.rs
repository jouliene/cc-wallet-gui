use zeroize::Zeroizing;

use crate::aead;
use crate::error::{VaultError, VaultResult};
use crate::keyslot::{self, KEYSLOT_LEN};
use crate::params::KdfParams;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Wallet,
    Activity,
    Journal,
}

impl Purpose {
    fn id(self) -> u8 {
        match self {
            Self::Wallet => 1,
            Self::Activity => 2,
            Self::Journal => 3,
        }
    }

    fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(Self::Wallet),
            2 => Some(Self::Activity),
            3 => Some(Self::Journal),
            _ => None,
        }
    }

    fn context(self) -> &'static str {
        match self {
            Self::Wallet => "cc-wallet vault v1 2026 · wallet",
            Self::Activity => "cc-wallet vault v1 2026 · activity",
            Self::Journal => "cc-wallet vault v1 2026 · journal",
        }
    }
}

const MAX_SECTIONS: usize = 8;
const DIR_ENTRY_LEN: usize = 5;

pub const MAX_HEADER_PROBE_LEN: usize = 4096;

pub const MAX_DISPLAY_NAME_BYTES: usize = 192;
const DISPLAY_NAME_LEN_BYTES: usize = 2;
const DEFAULT_DISPLAY_NAME: &str = "wallet";

fn section_frame_len(payload_len: usize) -> VaultResult<u32> {
    aead::NONCE_LEN
        .checked_add(payload_len)
        .and_then(|n| n.checked_add(aead::TAG_LEN))
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(VaultError::Corrupt("section body length exceeds u32"))
}

const SAVE_ID_LEN: usize = 16;

const COUNTER_LEN: usize = 8;

const DISPLAY_NAME_LEN_OFFSET: usize = KEYSLOT_LEN;
const DISPLAY_NAME_OFFSET: usize = DISPLAY_NAME_LEN_OFFSET + DISPLAY_NAME_LEN_BYTES;

#[derive(Clone, Copy)]
struct PublicHeader<'a> {
    display_name: &'a str,
    display_header: &'a [u8],
    save_id: &'a [u8],
    counter: u64,
    manifest_offset: usize,
}

#[derive(Debug)]
pub enum ActivitySection {
    Absent,
    Present(Zeroizing<Vec<u8>>),
    Corrupt,
}

pub struct OpenedContainer {
    pub vault: Vault,
    pub wallet: Zeroizing<Vec<u8>>,
    pub journal: Zeroizing<Vec<u8>>,
    pub activity: ActivitySection,
    pub save_counter: u64,
    pub has_unknown_sections: bool,
}

fn random_array<const N: usize>() -> VaultResult<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| VaultError::Rng)?;
    Ok(buf)
}

pub struct OpenedKeyslot {
    dek: Zeroizing<[u8; 32]>,
    params: KdfParams,
    keyslot: Vec<u8>,
}

pub struct Vault {
    params: KdfParams,
    dek: Zeroizing<[u8; 32]>,
    keyslot: Vec<u8>,
    display_name: String,
}

impl Vault {
    pub fn create(password: &[u8]) -> VaultResult<Self> {
        Self::create_named_with(password, KdfParams::DEFAULT, DEFAULT_DISPLAY_NAME)
    }

    pub fn create_with(password: &[u8], params: KdfParams) -> VaultResult<Self> {
        Self::create_named_with(password, params, DEFAULT_DISPLAY_NAME)
    }

    pub fn create_named_with(
        password: &[u8],
        params: KdfParams,
        display_name: impl Into<String>,
    ) -> VaultResult<Self> {
        let display_name = display_name.into();
        validate_display_name(&display_name).map_err(VaultError::InvalidDisplayName)?;
        let salt: [u8; 16] = random_array()?;
        let dek = Zeroizing::new(random_array::<32>()?);
        let keyslot = keyslot::build(password, params, &salt, &dek)?;
        Ok(Self {
            params,
            dek,
            keyslot,
            display_name,
        })
    }

    fn stream_key(&self, purpose: Purpose) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(blake3::derive_key(purpose.context(), &self.dek[..]))
    }

    fn section_aad(
        &self,
        purpose: Purpose,
        display_header: &[u8],
        save_id: &[u8],
        counter: u64,
        manifest: &[u8],
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            self.keyslot.len()
                + display_header.len()
                + save_id.len()
                + COUNTER_LEN
                + manifest.len()
                + 1,
        );
        aad.extend_from_slice(&self.keyslot);
        aad.extend_from_slice(display_header);
        aad.extend_from_slice(save_id);
        aad.extend_from_slice(&counter.to_le_bytes());
        aad.extend_from_slice(manifest);
        aad.push(purpose.id());
        aad
    }

    fn open_body(
        &self,
        purpose: Purpose,
        header: PublicHeader<'_>,
        manifest: &[u8],
        body: &[u8],
        on_fail: VaultError,
    ) -> VaultResult<Zeroizing<Vec<u8>>> {
        let key = self.stream_key(purpose);
        aead::open(
            &key,
            body,
            &self.section_aad(
                purpose,
                header.display_header,
                header.save_id,
                header.counter,
                manifest,
            ),
            on_fail,
        )
    }

    pub fn seal_container(
        &self,
        counter: u64,
        sections: &[(Purpose, &[u8])],
    ) -> VaultResult<Vec<u8>> {
        check_cardinality(sections.iter().map(|(p, _)| p.id()))?;

        let display_header = encode_display_header(&self.display_name);
        let save_id: [u8; SAVE_ID_LEN] = random_array()?;

        let mut manifest = Vec::with_capacity(1 + sections.len() * DIR_ENTRY_LEN);
        manifest.push(sections.len() as u8);
        for (purpose, payload) in sections {
            let body_len = section_frame_len(payload.len())?;
            manifest.push(purpose.id());
            manifest.extend_from_slice(&body_len.to_le_bytes());
        }

        let mut bodies = Vec::new();
        for (purpose, payload) in sections {
            let key = self.stream_key(*purpose);
            let body = aead::seal(
                &key,
                payload,
                &self.section_aad(*purpose, &display_header, &save_id, counter, &manifest),
            )?;
            bodies.extend_from_slice(&body);
        }

        let mut out = Vec::with_capacity(
            self.keyslot.len()
                + display_header.len()
                + SAVE_ID_LEN
                + COUNTER_LEN
                + manifest.len()
                + bodies.len(),
        );
        out.extend_from_slice(&self.keyslot);
        out.extend_from_slice(&display_header);
        out.extend_from_slice(&save_id);
        out.extend_from_slice(&counter.to_le_bytes());
        out.extend_from_slice(&manifest);
        out.extend_from_slice(&bodies);
        Ok(out)
    }

    pub fn open_keyslot(bytes: &[u8], password: &[u8]) -> VaultResult<OpenedKeyslot> {
        parse_public_header(bytes)?;
        let opened = keyslot::open(bytes, password)?;
        let keyslot = bytes[..KEYSLOT_LEN].to_vec();
        Ok(OpenedKeyslot {
            dek: opened.dek,
            params: opened.params,
            keyslot,
        })
    }

    pub fn open_container_with(bytes: &[u8], slot: &OpenedKeyslot) -> VaultResult<OpenedContainer> {
        let header = parse_public_header(bytes)?;
        if bytes.len() < KEYSLOT_LEN || bytes[..KEYSLOT_LEN] != slot.keyslot[..] {
            return Err(VaultError::WrongPassword);
        }
        let (manifest, sections) = parse_manifest(bytes, header.manifest_offset)?;
        check_cardinality(sections.iter().map(|(pid, _)| *pid))?;

        let vault = Self {
            params: slot.params,
            dek: slot.dek.clone(),
            keyslot: slot.keyslot.clone(),
            display_name: header.display_name.to_owned(),
        };

        let mut wallet: Option<Zeroizing<Vec<u8>>> = None;
        let mut journal: Option<Zeroizing<Vec<u8>>> = None;
        let mut activity = ActivitySection::Absent;
        for (pid, body) in sections {
            match Purpose::from_id(pid) {
                Some(Purpose::Wallet) => {
                    wallet = Some(vault.open_body(
                        Purpose::Wallet,
                        header,
                        manifest,
                        body,
                        VaultError::Corrupt("wallet payload"),
                    )?);
                }
                Some(Purpose::Journal) => {
                    journal = Some(vault.open_body(
                        Purpose::Journal,
                        header,
                        manifest,
                        body,
                        VaultError::Corrupt("journal payload"),
                    )?);
                }
                Some(Purpose::Activity) => {
                    activity = match vault.open_body(
                        Purpose::Activity,
                        header,
                        manifest,
                        body,
                        VaultError::Corrupt("activity payload"),
                    ) {
                        Ok(bytes) => ActivitySection::Present(bytes),
                        Err(_) => ActivitySection::Corrupt,
                    };
                }
                None => unreachable!("parse_manifest rejects unknown purpose ids"),
            }
        }

        let wallet = wallet.ok_or(VaultError::Corrupt("missing wallet section"))?;
        let journal = journal.ok_or(VaultError::Corrupt("missing journal section"))?;
        Ok(OpenedContainer {
            vault,
            wallet,
            journal,
            activity,
            save_counter: header.counter,
            has_unknown_sections: false,
        })
    }

    pub fn open_container(bytes: &[u8], password: &[u8]) -> VaultResult<OpenedContainer> {
        let slot = Self::open_keyslot(bytes, password)?;
        Self::open_container_with(bytes, &slot)
    }

    pub fn read_section(
        &self,
        purpose: Purpose,
        bytes: &[u8],
    ) -> VaultResult<Option<Zeroizing<Vec<u8>>>> {
        let header = parse_public_header(bytes)?;
        let (manifest, sections) = parse_manifest(bytes, header.manifest_offset)?;
        for (pid, body) in sections {
            if pid == purpose.id() {
                return self
                    .open_body(
                        purpose,
                        header,
                        manifest,
                        body,
                        VaultError::Corrupt("section payload"),
                    )
                    .map(Some);
            }
        }
        Ok(None)
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.params
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn verify_password(&self, password: &[u8]) -> bool {
        keyslot::open(&self.keyslot, password).is_ok()
    }
}

pub fn keyslot_prefix(bytes: &[u8]) -> Option<&[u8]> {
    bytes.get(..KEYSLOT_LEN)
}

pub fn read_kdf_params(bytes: &[u8]) -> VaultResult<KdfParams> {
    keyslot::validate_header(bytes)
}

pub fn read_display_name(bytes: &[u8]) -> VaultResult<&str> {
    Ok(parse_public_header(bytes)?.display_name)
}

pub fn read_save_counter(bytes: &[u8]) -> VaultResult<u64> {
    Ok(parse_public_header(bytes)?.counter)
}

pub fn looks_like_container(bytes: &[u8]) -> bool {
    let Ok(header) = parse_public_header(bytes) else {
        return false;
    };
    match parse_manifest(bytes, header.manifest_offset) {
        Ok((_, sections)) => check_cardinality(sections.iter().map(|(pid, _)| *pid)).is_ok(),
        Err(_) => false,
    }
}

fn validate_display_name(display_name: &str) -> Result<(), &'static str> {
    if display_name.trim().is_empty() {
        return Err("name must not be empty or whitespace-only");
    }
    if display_name.len() > MAX_DISPLAY_NAME_BYTES {
        return Err("UTF-8 name is too long");
    }
    if display_name.chars().any(char::is_control) {
        return Err("name must not contain control characters");
    }
    Ok(())
}

fn encode_display_header(display_name: &str) -> Vec<u8> {
    debug_assert!(validate_display_name(display_name).is_ok());
    let len = u16::try_from(display_name.len())
        .expect("MAX_DISPLAY_NAME_BYTES fits in the v1 u16 length field");
    let mut encoded = Vec::with_capacity(DISPLAY_NAME_LEN_BYTES + display_name.len());
    encoded.extend_from_slice(&len.to_le_bytes());
    encoded.extend_from_slice(display_name.as_bytes());
    encoded
}

fn parse_public_header(bytes: &[u8]) -> VaultResult<PublicHeader<'_>> {
    keyslot::validate_header(bytes)?;
    let raw_len = bytes
        .get(DISPLAY_NAME_LEN_OFFSET..DISPLAY_NAME_OFFSET)
        .ok_or(VaultError::Truncated)?;
    let display_name_len = u16::from_le_bytes(
        raw_len
            .try_into()
            .expect("two-byte display-name length slice"),
    ) as usize;
    if display_name_len > MAX_DISPLAY_NAME_BYTES {
        return Err(VaultError::Corrupt("display name is too long"));
    }
    let display_name_end = DISPLAY_NAME_OFFSET
        .checked_add(display_name_len)
        .ok_or(VaultError::Corrupt("display name length overflow"))?;
    let display_name_bytes = bytes
        .get(DISPLAY_NAME_OFFSET..display_name_end)
        .ok_or(VaultError::Truncated)?;
    let display_name = std::str::from_utf8(display_name_bytes)
        .map_err(|_| VaultError::Corrupt("display name is not valid UTF-8"))?;
    validate_display_name(display_name)
        .map_err(|_| VaultError::Corrupt("display name is invalid"))?;

    let save_id_offset = display_name_end;
    let counter_offset = save_id_offset
        .checked_add(SAVE_ID_LEN)
        .ok_or(VaultError::Corrupt("header offset overflow"))?;
    let manifest_offset = counter_offset
        .checked_add(COUNTER_LEN)
        .ok_or(VaultError::Corrupt("header offset overflow"))?;
    let save_id = bytes
        .get(save_id_offset..counter_offset)
        .ok_or(VaultError::Truncated)?;
    let raw_counter = bytes
        .get(counter_offset..manifest_offset)
        .ok_or(VaultError::Truncated)?;
    let counter = u64::from_le_bytes(
        raw_counter
            .try_into()
            .expect("eight-byte save-counter slice"),
    );
    let display_header = bytes
        .get(DISPLAY_NAME_LEN_OFFSET..display_name_end)
        .ok_or(VaultError::Truncated)?;
    Ok(PublicHeader {
        display_name,
        display_header,
        save_id,
        counter,
        manifest_offset,
    })
}

type ParsedManifest<'a> = (&'a [u8], Vec<(u8, &'a [u8])>);

fn decode_manifest_directory(
    bytes: &[u8],
    manifest_offset: usize,
) -> VaultResult<(usize, Vec<(u8, usize)>)> {
    let count = *bytes.get(manifest_offset).ok_or(VaultError::Truncated)? as usize;
    if count > MAX_SECTIONS {
        return Err(VaultError::Corrupt("section count too large"));
    }
    let manifest_end = manifest_offset
        .checked_add(1 + count * DIR_ENTRY_LEN)
        .ok_or(VaultError::Corrupt("manifest length overflow"))?;
    let manifest = bytes
        .get(manifest_offset..manifest_end)
        .ok_or(VaultError::Truncated)?;

    let mut entries: Vec<(u8, usize)> = Vec::with_capacity(count);
    let mut off = manifest_offset + 1;
    for _ in 0..count {
        let entry = &manifest[(off - manifest_offset)..(off - manifest_offset) + DIR_ENTRY_LEN];
        if Purpose::from_id(entry[0]).is_none() {
            return Err(VaultError::Corrupt("unknown section purpose"));
        }
        let len = u32::from_le_bytes([entry[1], entry[2], entry[3], entry[4]]) as usize;
        entries.push((entry[0], len));
        off += DIR_ENTRY_LEN;
    }
    Ok((manifest_end, entries))
}

fn parse_manifest(bytes: &[u8], manifest_offset: usize) -> VaultResult<ParsedManifest<'_>> {
    let (manifest_end, entries) = decode_manifest_directory(bytes, manifest_offset)?;
    let manifest = &bytes[manifest_offset..manifest_end];

    let mut sections = Vec::with_capacity(entries.len());
    let mut body_off = manifest_end;
    for (pid, len) in entries {
        let end = body_off
            .checked_add(len)
            .ok_or(VaultError::Corrupt("section length overflow"))?;
        let body = bytes
            .get(body_off..end)
            .ok_or(VaultError::Corrupt("section extent past end"))?;
        body_off = end;
        sections.push((pid, body));
    }
    if body_off != bytes.len() {
        return Err(VaultError::Corrupt("trailing bytes after last section"));
    }
    Ok((manifest, sections))
}

fn check_cardinality(ids: impl Iterator<Item = u8>) -> VaultResult<()> {
    let (mut wallet, mut journal, mut activity) = (0u32, 0u32, 0u32);
    for id in ids {
        match Purpose::from_id(id) {
            Some(Purpose::Wallet) => wallet += 1,
            Some(Purpose::Journal) => journal += 1,
            Some(Purpose::Activity) => activity += 1,
            None => return Err(VaultError::Corrupt("unknown section purpose")),
        }
    }
    if wallet != 1 {
        return Err(VaultError::Corrupt(
            "container must have exactly one wallet section",
        ));
    }
    if journal != 1 {
        return Err(VaultError::Corrupt(
            "container must have exactly one journal section",
        ));
    }
    if activity > 1 {
        return Err(VaultError::Corrupt(
            "container has more than one activity section",
        ));
    }
    Ok(())
}

pub fn container_declared_len(prefix: &[u8]) -> Option<u64> {
    let header = parse_public_header(prefix).ok()?;
    let (manifest_end, entries) = decode_manifest_directory(prefix, header.manifest_offset).ok()?;
    check_cardinality(entries.iter().map(|(pid, _)| *pid)).ok()?;
    let mut total = manifest_end as u64;
    for (_, len) in entries {
        total = total.checked_add(len as u64)?;
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::KdfParams;

    const CHEAP: KdfParams = KdfParams {
        m_kib: 32,
        t: 2,
        p: 1,
    };
    const PW: &[u8] = b"open sesame please";
    const WALLET: &[u8] = b"wallet-bytes";
    const JOURNAL: &[u8] = b"journal-bytes";
    const ACTIVITY: &[u8] = b"activity-bytes";

    fn vault() -> Vault {
        Vault::create_with(PW, CHEAP).unwrap()
    }

    fn seal_full(v: &Vault, counter: u64) -> Vec<u8> {
        v.seal_container(
            counter,
            &[
                (Purpose::Wallet, WALLET),
                (Purpose::Activity, ACTIVITY),
                (Purpose::Journal, JOURNAL),
            ],
        )
        .unwrap()
    }

    fn offsets(container: &[u8]) -> (usize, usize, usize) {
        let header = parse_public_header(container).unwrap();
        let manifest_offset = header.manifest_offset;
        let counter_offset = manifest_offset - COUNTER_LEN;
        let save_id_offset = counter_offset - SAVE_ID_LEN;
        (save_id_offset, counter_offset, manifest_offset)
    }

    #[test]
    fn container_declared_len_matches_sealed_output() {
        let v = vault();
        let bytes = seal_full(&v, 1);
        let cap = MAX_HEADER_PROBE_LEN.min(bytes.len());

        assert_eq!(container_declared_len(&bytes), Some(bytes.len() as u64));
        assert_eq!(
            container_declared_len(&bytes[..cap]),
            Some(bytes.len() as u64)
        );

        assert_ne!(
            container_declared_len(&bytes[..cap]),
            Some((bytes.len() - 1) as u64)
        );

        let mut padded = bytes.clone();
        padded.push(0);
        let padded_cap = MAX_HEADER_PROBE_LEN.min(padded.len());
        assert_ne!(
            container_declared_len(&padded[..padded_cap]),
            Some(padded.len() as u64)
        );

        assert!(looks_like_container(&bytes));
        assert_eq!(
            container_declared_len(&bytes[..cap]) == Some(bytes.len() as u64),
            looks_like_container(&bytes)
        );
        assert!(!looks_like_container(&padded));
        assert_eq!(
            container_declared_len(&padded[..padded_cap]) == Some(padded.len() as u64),
            looks_like_container(&padded)
        );

        assert_eq!(container_declared_len(b"not a container at all"), None);
        assert_eq!(container_declared_len(&[]), None);

        let big_wallet = vec![0xABu8; 8 * 1024];
        let big = v
            .seal_container(
                2,
                &[(Purpose::Wallet, &big_wallet), (Purpose::Journal, JOURNAL)],
            )
            .unwrap();
        assert!(big.len() > MAX_HEADER_PROBE_LEN);
        assert_eq!(
            container_declared_len(&big[..MAX_HEADER_PROBE_LEN]),
            Some(big.len() as u64),
            "declared length is computed from the header prefix, not the bodies"
        );
        assert!(looks_like_container(&big));
    }

    #[test]
    fn container_round_trips_all_sections_and_counter() {
        let file = seal_full(&vault(), 7);
        let opened = Vault::open_container(&file, PW).unwrap();
        assert_eq!(&opened.wallet[..], WALLET);
        assert_eq!(&opened.journal[..], JOURNAL);
        assert_eq!(opened.save_counter, 7);
        assert!(matches!(&opened.activity, ActivitySection::Present(a) if &a[..] == ACTIVITY));
        assert!(!opened.has_unknown_sections);
    }

    #[test]
    fn verify_password_checks_the_password_against_the_in_memory_keyslot() {
        let v = vault();
        assert!(v.verify_password(PW), "the creating password verifies");
        assert!(
            !v.verify_password(b"not the password"),
            "a wrong password is rejected"
        );
        assert!(!v.verify_password(b""), "an empty password is rejected");
    }

    #[test]
    fn open_container_with_reuses_a_cached_keyslot() {
        let file = seal_full(&vault(), 7);
        let slot = Vault::open_keyslot(&file, PW).unwrap();
        let via_cache = Vault::open_container_with(&file, &slot).unwrap();
        let via_full = Vault::open_container(&file, PW).unwrap();
        assert_eq!(&via_cache.wallet[..], &via_full.wallet[..]);
        assert_eq!(&via_cache.journal[..], &via_full.journal[..]);
        assert_eq!(via_cache.save_counter, via_full.save_counter);
        assert!(matches!(
            (&via_cache.activity, &via_full.activity),
            (ActivitySection::Present(a), ActivitySection::Present(b)) if a[..] == b[..]
        ));
    }

    #[test]
    fn a_cached_keyslot_rejects_a_container_from_another_generation() {
        let a = seal_full(&vault(), 1);
        let b = seal_full(&vault(), 1);
        let slot_a = Vault::open_keyslot(&a, PW).unwrap();
        assert!(matches!(
            Vault::open_container_with(&b, &slot_a),
            Err(VaultError::WrongPassword)
        ));
        assert!(Vault::open_container_with(&a, &slot_a).is_ok());
    }

    #[test]
    fn exact_display_name_is_public_and_round_trips_after_authentication() {
        let vault = Vault::create_named_with(PW, CHEAP, "My TON Wallet 💎").unwrap();
        assert_eq!(vault.display_name(), "My TON Wallet 💎");
        let file = seal_full(&vault, 1);

        assert_eq!(read_display_name(&file).unwrap(), "My TON Wallet 💎");
        let opened = Vault::open_container(&file, PW).unwrap();
        assert_eq!(opened.vault.display_name(), "My TON Wallet 💎");
    }

    #[test]
    fn display_name_tampering_is_visible_but_cannot_authenticate() {
        let vault = Vault::create_named_with(PW, CHEAP, "My TON Wallet").unwrap();
        let mut file = seal_full(&vault, 1);
        file[DISPLAY_NAME_OFFSET] = b'B';

        assert_eq!(read_display_name(&file).unwrap(), "By TON Wallet");
        assert!(matches!(
            Vault::open_container(&file, PW),
            Err(VaultError::Corrupt(_))
        ));
    }

    #[test]
    fn invalid_display_names_are_rejected_before_key_derivation() {
        for invalid in ["", "   ", "line\nbreak"] {
            assert!(matches!(
                Vault::create_named_with(PW, CHEAP, invalid),
                Err(VaultError::InvalidDisplayName(_))
            ));
        }
        let too_long = "x".repeat(MAX_DISPLAY_NAME_BYTES + 1);
        assert!(matches!(
            Vault::create_named_with(PW, CHEAP, too_long),
            Err(VaultError::InvalidDisplayName(_))
        ));

        let maximum = "x".repeat(MAX_DISPLAY_NAME_BYTES);
        assert!(Vault::create_named_with(PW, CHEAP, maximum).is_ok());
    }

    #[test]
    fn malformed_public_name_header_is_rejected_without_a_password() {
        let file = seal_full(&vault(), 1);

        let mut oversized = file.clone();
        oversized[DISPLAY_NAME_LEN_OFFSET..DISPLAY_NAME_OFFSET]
            .copy_from_slice(&((MAX_DISPLAY_NAME_BYTES + 1) as u16).to_le_bytes());
        assert!(matches!(
            read_display_name(&oversized),
            Err(VaultError::Corrupt("display name is too long"))
        ));
        assert!(!looks_like_container(&oversized));

        let mut invalid_utf8 = file;
        invalid_utf8[DISPLAY_NAME_OFFSET] = 0xff;
        assert!(matches!(
            read_display_name(&invalid_utf8),
            Err(VaultError::Corrupt("display name is not valid UTF-8"))
        ));
        assert!(!looks_like_container(&invalid_utf8));
    }

    #[test]
    fn an_empty_journal_round_trips() {
        let v = vault();
        let file = v
            .seal_container(1, &[(Purpose::Wallet, WALLET), (Purpose::Journal, b"")])
            .unwrap();
        let opened = Vault::open_container(&file, PW).unwrap();
        assert_eq!(&opened.wallet[..], WALLET);
        assert!(
            opened.journal.is_empty(),
            "an empty journal opens as empty, not absent"
        );
        assert!(matches!(opened.activity, ActivitySection::Absent));
    }

    #[test]
    fn read_save_counter_is_password_free_and_authenticated() {
        let file = seal_full(&vault(), 42);
        assert_eq!(read_save_counter(&file).unwrap(), 42);
        let mut tampered = file.clone();
        let (_, counter_offset, _) = offsets(&tampered);
        tampered[counter_offset] ^= 0x01;
        assert!(matches!(
            Vault::open_container(&tampered, PW),
            Err(VaultError::Corrupt(_))
        ));
    }

    #[test]
    fn a_missing_journal_section_fails_closed() {
        let file = vault()
            .seal_container(1, &[(Purpose::Wallet, WALLET), (Purpose::Journal, b"")])
            .unwrap();
        assert!(Vault::open_container(&file, PW).is_ok());
        assert!(matches!(
            vault().seal_container(1, &[(Purpose::Wallet, WALLET)]),
            Err(VaultError::Corrupt(
                "container must have exactly one journal section"
            ))
        ));
    }

    #[test]
    fn a_missing_wallet_section_is_rejected() {
        assert!(matches!(
            vault().seal_container(1, &[(Purpose::Journal, b"")]),
            Err(VaultError::Corrupt(
                "container must have exactly one wallet section"
            ))
        ));
    }

    #[test]
    fn duplicate_sections_are_rejected() {
        assert!(matches!(
            vault().seal_container(
                1,
                &[
                    (Purpose::Wallet, WALLET),
                    (Purpose::Wallet, WALLET),
                    (Purpose::Journal, b"")
                ]
            ),
            Err(VaultError::Corrupt(_))
        ));
    }

    #[test]
    fn wrong_password_comes_only_from_the_keyslot() {
        let file = seal_full(&vault(), 1);
        assert!(matches!(
            Vault::open_container(&file, b"wrong"),
            Err(VaultError::WrongPassword)
        ));
    }

    #[test]
    fn a_tampered_wallet_body_is_corrupt_not_wrong_password() {
        let v = vault();
        let file = v
            .seal_container(1, &[(Purpose::Wallet, WALLET), (Purpose::Journal, JOURNAL)])
            .unwrap();
        let last = file.len() - 1;
        let mut damaged = file.clone();
        damaged[last] ^= 0x01;
        assert!(matches!(
            Vault::open_container(&damaged, PW),
            Err(VaultError::Corrupt(_))
        ));
    }

    #[test]
    fn a_corrupt_activity_section_is_reported_corrupt_not_absent() {
        let file = seal_full(&vault(), 1);
        let mut damaged = file.clone();
        let (_, _, manifest_offset) = offsets(&damaged);
        let mid = manifest_offset
            + 1
            + 3 * DIR_ENTRY_LEN
            + aead::NONCE_LEN
            + aead::TAG_LEN
            + WALLET.len()
            + 5;
        damaged[mid] ^= 0x01;
        let opened = Vault::open_container(&damaged, PW).unwrap();
        assert_eq!(&opened.wallet[..], WALLET);
        assert_eq!(&opened.journal[..], JOURNAL);
        assert!(
            matches!(opened.activity, ActivitySection::Corrupt),
            "a damaged activity section is Corrupt, not Absent"
        );
    }

    #[test]
    fn a_manifest_tamper_breaks_authentication() {
        let file = seal_full(&vault(), 1);
        let mut tampered = file.clone();
        let (_, _, manifest_offset) = offsets(&tampered);
        let len_byte = manifest_offset + 1 + 1;
        tampered[len_byte] ^= 0x01;
        assert!(
            Vault::open_container(&tampered, PW).is_err(),
            "a tampered manifest must be rejected"
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut file = seal_full(&vault(), 1);
        file.push(0xAB);
        assert!(matches!(
            Vault::open_container(&file, PW),
            Err(VaultError::Corrupt("trailing bytes after last section"))
        ));
    }

    #[test]
    fn an_unknown_purpose_id_is_rejected_not_flagged() {
        let clean = vault()
            .seal_container(1, &[(Purpose::Wallet, WALLET), (Purpose::Journal, b"")])
            .unwrap();
        let injected = inject_unknown_section(&clean, 9, b"a future section");
        assert!(matches!(
            Vault::open_container(&injected, PW),
            Err(VaultError::Corrupt("unknown section purpose"))
        ));
    }

    #[test]
    fn a_hostile_section_count_is_rejected_before_slicing() {
        let file = seal_full(&vault(), 1);
        let mut too_many = file.clone();
        let (_, _, manifest_offset) = offsets(&too_many);
        too_many[manifest_offset] = 200;
        assert!(matches!(
            Vault::open_container(&too_many, PW),
            Err(VaultError::Corrupt("section count too large"))
        ));
    }

    #[test]
    fn sections_are_bound_to_their_save_so_splicing_is_rejected() {
        let v = vault();
        let save_a = seal_full(&v, 1);
        let save_b = seal_full(&v, 2);
        let (save_id_offset, counter_offset, _) = offsets(&save_a);
        assert_ne!(
            &save_a[save_id_offset..counter_offset],
            &save_b[save_id_offset..counter_offset],
            "each save must carry a fresh save-id"
        );
        let mut spliced = save_b.clone();
        let id_a = save_a[save_id_offset..counter_offset].to_vec();
        spliced[save_id_offset..counter_offset].copy_from_slice(&id_a);
        assert!(matches!(
            Vault::open_container(&spliced, PW),
            Err(VaultError::Corrupt(_))
        ));
        assert!(Vault::open_container(&save_a, PW).is_ok());
        assert!(Vault::open_container(&save_b, PW).is_ok());
    }

    #[test]
    fn a_non_v1_version_container_is_cleanly_rejected() {
        let file = seal_full(&vault(), 1);
        for bogus in [0u16, 2u16, 3u16, 99u16] {
            let mut tampered = file.clone();
            tampered[8..10].copy_from_slice(&bogus.to_le_bytes());
            assert!(
                matches!(
                    Vault::open_container(&tampered, PW),
                    Err(VaultError::UnsupportedFormat(_))
                ),
                "version {bogus} must be rejected on the version gate"
            );
        }
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext_seed() {
        let secret = b"canary-seed-phrase-marker";
        let file = vault()
            .seal_container(1, &[(Purpose::Wallet, secret), (Purpose::Journal, b"")])
            .unwrap();
        assert!(
            file.windows(secret.len()).all(|w| w != secret),
            "plaintext seed leaked into the vault container"
        );
    }

    #[test]
    fn section_frame_len_rejects_oversized_payloads_without_allocating() {
        assert!(section_frame_len(0).is_ok());
        assert!(matches!(
            section_frame_len(usize::MAX),
            Err(VaultError::Corrupt(_))
        ));
        assert!(
            matches!(
                section_frame_len(u32::MAX as usize),
                Err(VaultError::Corrupt(_))
            ),
            "nonce+tag pushes a u32::MAX payload past the u32 extent"
        );
    }

    #[test]
    fn looks_like_container_accepts_only_a_structurally_complete_container() {
        let file = seal_full(&vault(), 1);
        assert!(looks_like_container(&file));
        assert!(!looks_like_container(b""));
        assert!(!looks_like_container(b"CCWALLET"));
        for cut in [
            KEYSLOT_LEN,
            KEYSLOT_LEN + 8,
            offsets(&file).2,
            file.len() - 20,
            file.len() - 1,
        ] {
            assert!(
                !looks_like_container(&file[..cut]),
                "a container torn at {cut} bytes must be rejected, not promoted"
            );
            assert!(
                Vault::open_container(&file[..cut], PW).is_err(),
                "the rejected {cut}-byte prefix is indeed unopenable"
            );
        }
        let no_journal_shape = {
            let mut m = file.clone();
            let (_, _, manifest_offset) = offsets(&m);
            m[manifest_offset] = 0;
            m
        };
        assert!(!looks_like_container(&no_journal_shape));
    }

    fn inject_unknown_section(container: &[u8], pid: u8, payload: &[u8]) -> Vec<u8> {
        let (_, _, manifest_offset) = offsets(container);
        let count = container[manifest_offset] as usize;
        let entries_start = manifest_offset + 1;
        let bodies_start = entries_start + count * DIR_ENTRY_LEN;
        let body_len = (aead::NONCE_LEN + payload.len() + aead::TAG_LEN) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&container[..manifest_offset]);
        out.push((count + 1) as u8);
        out.extend_from_slice(&container[entries_start..bodies_start]);
        out.push(pid);
        out.extend_from_slice(&body_len.to_le_bytes());
        out.extend_from_slice(&container[bodies_start..]);
        out.extend_from_slice(&vec![0u8; body_len as usize]);
        out
    }
}
