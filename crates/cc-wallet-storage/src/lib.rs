mod atomic;
mod error;
mod paths;
mod vault_store;

pub use error::{StorageError, StorageResult};
pub use paths::{
    InstanceLock, LOCK_FILE, LockOutcome, StartupCwd, acquire_single_instance_lock,
    resolve_startup_cwd,
};
pub use vault_store::{
    DEFAULT_WALLET_NAME, SelectedCandidate, VaultStore, VaultStoreResult, VaultWriter, WALLET_EXT,
    WalletListing, WriteReceipt, list_wallet_entries, list_wallets,
};
