use std::fmt;
use std::io;
use std::path::PathBuf;

#[derive(Debug)]
pub enum StorageError {
    CurrentDirectory(io::Error),
    InvalidStartupRoot { path: PathBuf, reason: String },
}

impl StorageError {
    pub fn invalid_startup_root(path: PathBuf, reason: impl Into<String>) -> Self {
        Self::InvalidStartupRoot {
            path,
            reason: reason.into(),
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentDirectory(error) => write!(
                f,
                "Could not access the folder CC Wallet was started from: {error}"
            ),
            Self::InvalidStartupRoot { path: _, reason } => write!(
                f,
                "CC Wallet cannot use the folder it was started from: {reason}"
            ),
        }
    }
}

impl std::error::Error for StorageError {}

pub type StorageResult<T> = Result<T, StorageError>;
