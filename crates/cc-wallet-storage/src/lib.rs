mod atomic;
mod error;
pub mod paths;
pub mod vault_store;

pub use error::{StorageError, StorageResult};
pub use paths::{
    InstanceLock, LOCK_FILE, LockOutcome, StartupCwd, acquire_single_instance_lock,
    resolve_startup_cwd,
};
pub use vault_store::{
    DEFAULT_WALLET_NAME, DestroyArtifactKind, DestroyArtifactOutcome, DestroyError, DestroyReport,
    OverwriteOutcome, PreparedVaultWrite, SelectedCandidate, UnlockedVault, VaultStore,
    VaultStoreError, VaultStoreResult, VaultWriter, WALLET_EXT, WalletListing, WriteReceipt,
    list_wallet_entries, list_wallets,
};
