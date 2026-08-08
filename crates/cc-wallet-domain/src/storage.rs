use std::fmt;

pub const MAX_RECORD_TITLE_BYTES: usize = 128;

pub const MAX_RECORD_DATA_BYTES: usize = 1024;

pub const RECORD_FRAMING_BYTES: usize = 2;

pub const STORAGE_KEY_CONTEXT: &str = "cc-wallet storage record key v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    EmptyTitle,
    TitleTooLong(usize),
    DataTooLong(usize),
    Full(u16),
    Malformed(&'static str),
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTitle => formatter.write_str("give the record a name"),
            Self::TitleTooLong(bytes) => write!(
                formatter,
                "the name is {bytes} bytes; the limit is {MAX_RECORD_TITLE_BYTES}"
            ),
            Self::DataTooLong(bytes) => write!(
                formatter,
                "the record is {bytes} bytes; the limit is {MAX_RECORD_DATA_BYTES}"
            ),
            Self::Full(limit) => write!(formatter, "the storage already holds {limit} records"),
            Self::Malformed(what) => write!(formatter, "the record could not be read: {what}"),
        }
    }
}

impl std::error::Error for StorageError {}

pub type StorageResult<T> = Result<T, StorageError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageRecord {
    pub id: u32,
    pub title: String,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageOp {
    Create,
    Put {
        id: u32,
        title: String,
        data: String,
    },
    Delete {
        id: u32,
    },
}

impl StorageOp {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Create => "create storage",
            Self::Put { .. } => "save record",
            Self::Delete { .. } => "delete record",
        }
    }

    pub fn record_id(&self) -> Option<u32> {
        match self {
            Self::Create => None,
            Self::Put { id, .. } | Self::Delete { id } => Some(*id),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StorageSnapshot {
    pub address: String,
    pub exists: bool,
    pub balance: u128,
    pub records: Vec<StorageRecord>,
    pub unreadable: usize,
}

impl StorageSnapshot {
    pub fn is_full(&self, limit: u16) -> bool {
        self.records.len() >= usize::from(limit)
    }

    pub fn contains(&self, id: u32) -> bool {
        self.records.iter().any(|record| record.id == id)
    }
}

pub fn validate_record(title: &str, data: &str) -> StorageResult<()> {
    let title = title.trim();
    if title.is_empty() {
        return Err(StorageError::EmptyTitle);
    }
    if title.len() > MAX_RECORD_TITLE_BYTES {
        return Err(StorageError::TitleTooLong(title.len()));
    }
    if data.len() > MAX_RECORD_DATA_BYTES {
        return Err(StorageError::DataTooLong(data.len()));
    }
    Ok(())
}

pub fn encode_record(title: &str, data: &str) -> StorageResult<Vec<u8>> {
    validate_record(title, data)?;
    let title = title.trim();
    let mut out = Vec::with_capacity(RECORD_FRAMING_BYTES + title.len() + data.len());
    out.extend_from_slice(&(title.len() as u16).to_be_bytes());
    out.extend_from_slice(title.as_bytes());
    out.extend_from_slice(data.as_bytes());
    Ok(out)
}

pub fn decode_record(bytes: &[u8]) -> StorageResult<(String, String)> {
    if bytes.len() < RECORD_FRAMING_BYTES {
        return Err(StorageError::Malformed("it is shorter than its own header"));
    }
    let (header, rest) = bytes.split_at(RECORD_FRAMING_BYTES);
    let title_len = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if title_len > rest.len() {
        return Err(StorageError::Malformed("the name runs past the end"));
    }
    let (title, data) = rest.split_at(title_len);
    let title = String::from_utf8(title.to_vec())
        .map_err(|_| StorageError::Malformed("the name is not valid text"))?;
    let data = String::from_utf8(data.to_vec())
        .map_err(|_| StorageError::Malformed("the contents are not valid text"))?;
    Ok((title, data))
}

pub fn record_aad(owner_address: &str, id: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(owner_address.len() + 4);
    aad.extend_from_slice(owner_address.as_bytes());
    aad.extend_from_slice(&id.to_be_bytes());
    aad
}

pub fn next_free_id(taken: &[u32], limit: u16) -> StorageResult<u32> {
    let mut sorted: Vec<u32> = taken.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() >= usize::from(limit) {
        return Err(StorageError::Full(limit));
    }
    let mut candidate = 1u32;
    for id in sorted {
        if id > candidate {
            break;
        }
        if id == candidate {
            candidate += 1;
        }
    }
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_round_trips_through_its_framing() {
        let (title, data) =
            decode_record(&encode_record("Inna's phone", "86594423664").unwrap()).unwrap();
        assert_eq!(title, "Inna's phone");
        assert_eq!(data, "86594423664");
    }

    #[test]
    fn framing_keeps_the_two_fields_apart_whatever_they_contain() {
        for (title, data) in [
            ("", "only data"),
            ("only title", ""),
            ("a", ""),
            ("телефон Инны", "8 659 442 36 64"),
            ("name with \u{0}nul", "data\nwith\nnewlines"),
            ("emoji 🔐", "and 🗝 in the value too"),
        ] {
            if title.trim().is_empty() {
                assert!(encode_record(title, data).is_err());
                continue;
            }
            let (back_title, back_data) =
                decode_record(&encode_record(title, data).unwrap()).unwrap();
            assert_eq!(back_title, title.trim());
            assert_eq!(back_data, data);
        }
    }

    #[test]
    fn a_title_that_looks_like_the_data_is_still_split_correctly() {
        let confusing = "abcabc";
        let (title, data) = decode_record(&encode_record(confusing, confusing).unwrap()).unwrap();
        assert_eq!(title, confusing);
        assert_eq!(data, confusing);
    }

    #[test]
    fn the_limits_are_enforced_on_bytes_not_characters() {
        assert_eq!(
            validate_record("", "x"),
            Err(StorageError::EmptyTitle),
            "a blank name is refused"
        );
        assert_eq!(validate_record("   ", "x"), Err(StorageError::EmptyTitle));

        let long_title = "x".repeat(MAX_RECORD_TITLE_BYTES);
        assert!(validate_record(&long_title, "").is_ok());
        assert_eq!(
            validate_record(&format!("{long_title}x"), ""),
            Err(StorageError::TitleTooLong(MAX_RECORD_TITLE_BYTES + 1))
        );

        let cyrillic = "я".repeat(MAX_RECORD_TITLE_BYTES / 2 + 1);
        assert!(cyrillic.chars().count() <= MAX_RECORD_TITLE_BYTES);
        assert!(matches!(
            validate_record(&cyrillic, ""),
            Err(StorageError::TitleTooLong(_))
        ));

        let long_data = "y".repeat(MAX_RECORD_DATA_BYTES);
        assert!(validate_record("name", &long_data).is_ok());
        assert_eq!(
            validate_record("name", &format!("{long_data}y")),
            Err(StorageError::DataTooLong(MAX_RECORD_DATA_BYTES + 1))
        );
    }

    #[test]
    fn a_full_size_record_still_fits_the_contracts_blob_budget() {
        let sealed = RECORD_FRAMING_BYTES
            + MAX_RECORD_TITLE_BYTES
            + MAX_RECORD_DATA_BYTES
            + cc_wallet_vault::RECORD_SEAL_OVERHEAD;
        assert!(
            sealed <= 2032,
            "the largest record the form accepts is {sealed} bytes on chain"
        );
    }

    #[test]
    fn a_malformed_blob_is_refused_rather_than_guessed_at() {
        assert!(decode_record(&[]).is_err());
        assert!(decode_record(&[0]).is_err());
        assert!(
            decode_record(&[0x00, 0x05, b'a']).is_err(),
            "a name longer than the payload is a lie about the framing"
        );
        assert!(
            decode_record(&[0x00, 0x01, 0xff, 0xfe]).is_err(),
            "bytes that are not text are refused"
        );
        assert!(decode_record(&[0x00, 0x00]).is_ok());
    }

    #[test]
    fn the_aad_names_exactly_one_slot_of_exactly_one_owner() {
        let owner = "0:248f89d7b06fbed0a3d96302ca7d9afa6baba5ad476bbfbc0099396dd0016258";
        let other = "0:1111111111111111111111111111111111111111111111111111111111111111";

        assert_eq!(record_aad(owner, 1), record_aad(owner, 1));
        assert_ne!(record_aad(owner, 1), record_aad(owner, 2));
        assert_ne!(record_aad(owner, 1), record_aad(other, 1));
        assert!(record_aad(owner, 0x0102_0304).ends_with(&[1, 2, 3, 4]));
    }

    #[test]
    fn the_next_number_fills_the_lowest_gap_so_numbering_stays_tight() {
        assert_eq!(next_free_id(&[], 512).unwrap(), 1);
        assert_eq!(next_free_id(&[1, 2, 3], 512).unwrap(), 4);
        assert_eq!(
            next_free_id(&[1, 3, 4], 512).unwrap(),
            2,
            "a deleted record frees its number for reuse"
        );
        assert_eq!(next_free_id(&[2, 3], 512).unwrap(), 1);
        assert_eq!(
            next_free_id(&[3, 1, 2], 512).unwrap(),
            4,
            "the order the chain returns ids in does not matter"
        );
        assert_eq!(next_free_id(&[1, 1, 2], 512).unwrap(), 3);
    }

    #[test]
    fn a_full_storage_refuses_to_name_another_record() {
        let taken: Vec<u32> = (1..=4).collect();
        assert_eq!(next_free_id(&taken, 4), Err(StorageError::Full(4)));
        assert_eq!(next_free_id(&taken, 5).unwrap(), 5);
    }

    #[test]
    fn a_snapshot_answers_what_the_form_needs_to_know() {
        let snapshot = StorageSnapshot {
            address: "0:aa".to_owned(),
            exists: true,
            balance: 1,
            records: vec![StorageRecord {
                id: 2,
                title: "t".to_owned(),
                data: "d".to_owned(),
            }],
            unreadable: 0,
        };
        assert!(snapshot.contains(2));
        assert!(!snapshot.contains(1));
        assert!(snapshot.is_full(1));
        assert!(!snapshot.is_full(2));
    }
}
