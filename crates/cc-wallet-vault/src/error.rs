use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    WrongPassword,
    InvalidDisplayName(&'static str),
    Corrupt(&'static str),
    Truncated,
    UnsupportedFormat(&'static str),
    ParamsRejected(&'static str),
    Crypto(&'static str),
    Rng,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPassword => f.write_str("wrong password or damaged vault"),
            Self::InvalidDisplayName(what) => write!(f, "invalid wallet display name: {what}"),
            Self::Corrupt(what) => write!(f, "vault payload is corrupt: {what}"),
            Self::Truncated => f.write_str("vault file is truncated"),
            Self::UnsupportedFormat(what) => write!(f, "unsupported vault format: {what}"),
            Self::ParamsRejected(what) => write!(f, "vault KDF parameters rejected: {what}"),
            Self::Crypto(what) => write!(f, "vault cryptography failed: {what}"),
            Self::Rng => f.write_str("failed to read OS entropy"),
        }
    }
}

impl std::error::Error for VaultError {}

pub type VaultResult<T> = Result<T, VaultError>;
