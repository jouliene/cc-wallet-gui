use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletError {
    Validation(String),
    Amount(String),
    Overflow(String),
}

pub type WalletResult<T> = Result<T, WalletError>;

impl WalletError {
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    pub fn amount(message: impl Into<String>) -> Self {
        Self::Amount(message.into())
    }

    pub fn overflow(message: impl Into<String>) -> Self {
        Self::Overflow(message.into())
    }
}

impl fmt::Display for WalletError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(message) | Self::Amount(message) | Self::Overflow(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl std::error::Error for WalletError {}
