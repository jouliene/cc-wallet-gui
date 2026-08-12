use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

use cc_wallet_vault::{
    ActivitySection, OpenedContainer, Purpose, Vault, VaultError, read_save_counter,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::atomic;

fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn io_at_path(operation: &str, path: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{operation} {} failed: {error}", absolute(path).display()),
    )
}

pub(crate) fn read_regular_nofollow(path: &Path) -> io::Result<Vec<u8>> {
    let initial = fs::symlink_metadata(path)
        .map_err(|error| io_at_path("reading wallet artifact metadata at", path, error))?;
    if !initial.is_file() || initial.file_type().is_symlink() || has_multiple_links(&initial) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "wallet artifact is not a singly-linked regular file: {}",
                absolute(path).display()
            ),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|error| {
        io_at_path(
            "opening wallet artifact without following links at",
            path,
            error,
        )
    })?;
    let opened = file
        .metadata()
        .map_err(|error| io_at_path("reading opened wallet artifact metadata at", path, error))?;
    if !same_identity(&initial, &opened) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "wallet artifact changed while opening: {}",
                absolute(path).display()
            ),
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| io_at_path("reading wallet artifact at", path, error))?;
    let final_metadata = fs::symlink_metadata(path)
        .map_err(|error| io_at_path("rechecking wallet artifact metadata at", path, error))?;
    if !same_identity(&opened, &final_metadata) || opened.len() != bytes.len() as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "wallet artifact changed while reading: {}",
                absolute(path).display()
            ),
        ));
    }
    Ok(bytes)
}

pub(crate) fn read_prefix_nofollow(path: &Path, cap: usize) -> io::Result<(Vec<u8>, u64)> {
    let initial = fs::symlink_metadata(path)
        .map_err(|error| io_at_path("reading wallet artifact metadata at", path, error))?;
    if !initial.is_file() || initial.file_type().is_symlink() || has_multiple_links(&initial) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "wallet artifact is not a singly-linked regular file: {}",
                absolute(path).display()
            ),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|error| {
        io_at_path(
            "opening wallet artifact without following links at",
            path,
            error,
        )
    })?;
    let opened = file
        .metadata()
        .map_err(|error| io_at_path("reading opened wallet artifact metadata at", path, error))?;
    if !same_identity(&initial, &opened) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "wallet artifact changed while opening: {}",
                absolute(path).display()
            ),
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(cap as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| io_at_path("reading wallet artifact at", path, error))?;
    let final_metadata = fs::symlink_metadata(path)
        .map_err(|error| io_at_path("rechecking wallet artifact metadata at", path, error))?;
    if !same_identity(&opened, &final_metadata) || opened.len() != final_metadata.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "wallet artifact changed while reading: {}",
                absolute(path).display()
            ),
        ));
    }
    Ok((bytes, opened.len()))
}

fn is_container_by_header(path: &Path) -> io::Result<bool> {
    let (prefix, file_len) = read_prefix_nofollow(path, cc_wallet_vault::MAX_HEADER_PROBE_LEN)?;
    Ok(cc_wallet_vault::container_declared_len(&prefix) == Some(file_len))
}

#[derive(Debug, Clone)]
pub struct SelectedCandidate {
    owner_main: PathBuf,
    path: PathBuf,
    counter: u64,
    sha256: [u8; 32],
}

impl SelectedCandidate {
    pub fn exact_path(&self) -> &Path {
        &self.path
    }

    pub fn save_counter(&self) -> u64 {
        self.counter
    }

    pub fn file_sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

pub const DEFAULT_WALLET_NAME: &str = "wallet";

pub const WALLET_EXT: &str = "ccwallet";

const MAX_CANDIDATE_CONTAINER_BYTES: u64 = 32 * 1024 * 1024;

fn main_file(name: &str) -> String {
    format!("{name}.{WALLET_EXT}")
}

fn validate_wallet_name(name: &str) -> VaultStoreResult<()> {
    let reject = |reason: &str| {
        Err(VaultStoreError::WriterState(format!(
            "invalid wallet name {name:?}: {reason}"
        )))
    };
    if name.is_empty() {
        return reject("empty");
    }
    if name == "." || name == ".." {
        return reject("is a path component");
    }
    if name
        .chars()
        .any(|c| std::path::is_separator(c) || c == '\\')
    {
        return reject("contains a path separator");
    }
    if name.chars().any(char::is_control) {
        return reject("contains a control character");
    }
    if name.to_lowercase().contains(&format!(".{WALLET_EXT}")) {
        return reject("contains the wallet extension");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletListing {
    pub storage_id: String,
    pub display_name: String,
}

pub fn list_wallets(dir: &Path) -> VaultStoreResult<Vec<String>> {
    let ext = format!(".{WALLET_EXT}");
    let survivor_marker = format!("{ext}.");
    let mut names: Vec<String> = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(names),
        Err(error) => {
            return Err(VaultStoreError::Io(io_at_path(
                "reading wallet directory",
                dir,
                error,
            )));
        }
    };
    for entry in entries {
        let entry = entry.map_err(|error| {
            VaultStoreError::Io(io_at_path("reading wallet directory entry", dir, error))
        })?;
        let raw = entry.file_name();
        let Some(file_name) = raw.to_str() else {
            continue;
        };
        if let Some(stem) = file_name.strip_suffix(&ext)
            && !stem.is_empty()
            && validate_wallet_name(stem).is_ok()
        {
            names.push(stem.to_owned());
            continue;
        }
        if (file_name.ends_with(".tmp") || file_name.ends_with(".orphan"))
            && let Some((stem, _)) = file_name.split_once(&survivor_marker)
            && !stem.is_empty()
            && validate_wallet_name(stem).is_ok()
            && match is_container_by_header(&entry.path()) {
                Ok(is_container) => is_container,
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(_) => true,
            }
        {
            names.push(stem.to_owned());
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

pub fn list_wallet_entries(dir: &Path) -> VaultStoreResult<Vec<WalletListing>> {
    Ok(list_wallets(dir)?
        .into_iter()
        .map(|storage_id| {
            let store = VaultStore::new(dir.to_path_buf(), storage_id.clone());
            let display_name = store
                .read_display_name()
                .ok()
                .flatten()
                .unwrap_or_else(|| storage_id.clone());
            WalletListing {
                storage_id,
                display_name,
            }
        })
        .collect())
}

#[derive(Debug)]
pub enum VaultStoreError {
    WrongPassword,
    Vault(VaultError),
    Io(io::Error),
    WriterState(String),
}

impl VaultStoreError {
    fn from_vault(error: VaultError) -> Self {
        match error {
            VaultError::WrongPassword => Self::WrongPassword,
            other => Self::Vault(other),
        }
    }

    pub fn is_wrong_password(&self) -> bool {
        matches!(self, Self::WrongPassword)
    }

    pub fn is_unsupported_format(&self) -> bool {
        matches!(self, Self::Vault(VaultError::UnsupportedFormat(_)))
    }
}

impl fmt::Display for VaultStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPassword => f.write_str("wrong password or damaged wallet"),
            Self::Vault(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "{error}"),
            Self::WriterState(detail) => write!(f, "wallet writer state error: {detail}"),
        }
    }
}

impl std::error::Error for VaultStoreError {}

impl From<io::Error> for VaultStoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub type VaultStoreResult<T> = Result<T, VaultStoreError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestroyArtifactKind {
    Main,
    Temporary,
    QuarantineOrphan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverwriteOutcome {
    Completed { bytes: u64 },
    SkippedSymlink,
    Incomplete { bytes: u64 },
    UnsupportedFileType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestroyArtifactOutcome {
    path: PathBuf,
    kind: DestroyArtifactKind,
    overwrite: OverwriteOutcome,
    unlinked: bool,
    directory_synced: bool,
}

impl DestroyArtifactOutcome {
    pub fn exact_path(&self) -> &Path {
        &self.path
    }

    pub fn kind(&self) -> DestroyArtifactKind {
        self.kind
    }

    pub fn overwrite(&self) -> &OverwriteOutcome {
        &self.overwrite
    }

    pub fn was_unlinked(&self) -> bool {
        self.unlinked
    }

    pub fn directory_was_synced(&self) -> bool {
        self.directory_synced
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestroyReport {
    artifacts: Vec<DestroyArtifactOutcome>,
    residues: Vec<PathBuf>,
    active_lock: Option<PathBuf>,
}

impl DestroyReport {
    pub fn artifacts(&self) -> &[DestroyArtifactOutcome] {
        &self.artifacts
    }

    pub fn residues(&self) -> &[PathBuf] {
        &self.residues
    }

    pub fn active_lock(&self) -> Option<&Path> {
        self.active_lock.as_deref()
    }
}

#[derive(Debug)]
pub struct DestroyError {
    operation: &'static str,
    path: PathBuf,
    source: io::Error,
    report: Box<DestroyReport>,
    residue_scan_error: Option<String>,
}

impl DestroyError {
    pub fn report(&self) -> &DestroyReport {
        &self.report
    }
}

impl fmt::Display for DestroyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} failed: {}",
            self.operation,
            self.path.display(),
            self.source
        )?;
        if self.report.residues.is_empty() {
            formatter.write_str("; no ciphertext residue was visible after the failure")?;
        } else {
            let paths = self
                .report
                .residues
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            write!(formatter, "; ciphertext residues: {paths}")?;
        }
        if let Some(scan_error) = &self.residue_scan_error {
            write!(formatter, "; residue scan also failed: {scan_error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for DestroyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct WriteReceipt {
    counter: u64,
    exact_path: PathBuf,
    file_sha256: [u8; 32],
}

impl WriteReceipt {
    pub fn save_counter(&self) -> u64 {
        self.counter
    }

    pub fn exact_path(&self) -> &Path {
        &self.exact_path
    }

    pub fn file_sha256(&self) -> &[u8; 32] {
        &self.file_sha256
    }
}

pub struct PreparedVaultWrite {
    counter: u64,
    target: PathBuf,
    sealed: Zeroizing<Vec<u8>>,
    sealed_sha256: [u8; 32],
    fresh: bool,
}

impl PreparedVaultWrite {
    pub fn save_counter(&self) -> u64 {
        self.counter
    }

    pub fn execute(self) -> VaultStoreResult<WriteReceipt> {
        let embedded = read_save_counter(&self.sealed).map_err(VaultStoreError::from_vault)?;
        if embedded != self.counter {
            return Err(VaultStoreError::WriterState(
                "sealed counter differs from the reserved counter".to_owned(),
            ));
        }
        if self.fresh {
            atomic::write_atomic_new(&self.target, &self.sealed)?;
        } else {
            atomic::write_atomic(&self.target, &self.sealed)?;
        }
        let installed = read_regular_nofollow(&self.target)?;
        if installed.as_slice() != self.sealed.as_slice() {
            return Err(VaultStoreError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "installed wallet bytes differ from the reserved sealed write",
            )));
        }
        Ok(WriteReceipt {
            counter: self.counter,
            exact_path: self.target,
            file_sha256: self.sealed_sha256,
        })
    }
}

pub struct VaultWriter {
    store: VaultStore,
    committed_counter: u64,
    committed_sha256: Option<[u8; 32]>,
    pending: Option<PendingWrite>,
    healthy: bool,
}

#[derive(Debug)]
struct PendingWrite {
    counter: u64,
    exact_path: PathBuf,
    file_sha256: [u8; 32],
}

impl fmt::Debug for VaultWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultWriter")
            .field("path", &self.store.main_path())
            .field("committed_counter", &self.committed_counter)
            .field("has_committed_hash", &self.committed_sha256.is_some())
            .field(
                "pending_counter",
                &self.pending.as_ref().map(|write| write.counter),
            )
            .field("healthy", &self.healthy)
            .finish()
    }
}

impl VaultWriter {
    fn fresh(store: VaultStore) -> VaultStoreResult<Self> {
        let main = store.main_path();
        match fs::symlink_metadata(&main) {
            Ok(_) => {
                return Err(VaultStoreError::Io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("wallet already exists at {}", main.display()),
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if !atomic::try_list_temps(&main)?.is_empty()
            || !atomic::try_list_orphans(&main)?.is_empty()
        {
            return Err(VaultStoreError::WriterState(
                "a fresh wallet cannot start while recovery candidates exist".to_owned(),
            ));
        }
        Ok(Self {
            store,
            committed_counter: 0,
            committed_sha256: None,
            pending: None,
            healthy: true,
        })
    }

    fn authenticated(store: VaultStore, selected: &SelectedCandidate) -> VaultStoreResult<Self> {
        if selected.owner_main != store.main_path() {
            return Err(VaultStoreError::WriterState(
                "authenticated candidate belongs to a different wallet path".to_owned(),
            ));
        }
        let bytes = read_regular_nofollow(&selected.path)?;
        if hash_bytes(&bytes) != selected.sha256
            || read_save_counter(&bytes).map_err(VaultStoreError::from_vault)? != selected.counter
        {
            return Err(VaultStoreError::WriterState(
                "authenticated selected-candidate binding changed before writer ownership"
                    .to_owned(),
            ));
        }
        Ok(Self {
            store,
            committed_counter: selected.counter,
            committed_sha256: Some(selected.sha256),
            pending: None,
            healthy: true,
        })
    }

    pub fn committed_counter(&self) -> u64 {
        self.committed_counter
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy && self.pending.is_none()
    }

    pub fn has_pending_write(&self) -> bool {
        self.pending.is_some()
    }

    pub fn poison(&mut self) -> VaultStoreResult<()> {
        if self.pending.is_some() {
            return Err(VaultStoreError::WriterState(
                "cannot poison away a started write before consuming its result".to_owned(),
            ));
        }
        self.healthy = false;
        Ok(())
    }

    pub fn prepare(
        &mut self,
        vault: &Vault,
        wallet: &[u8],
        journal: &[u8],
        activity: Option<&[u8]>,
    ) -> VaultStoreResult<PreparedVaultWrite> {
        if !self.healthy {
            return Err(VaultStoreError::WriterState(
                "writer is unhealthy after an earlier persistence failure".to_owned(),
            ));
        }
        if self.pending.is_some() {
            return Err(VaultStoreError::WriterState(
                "a started write has not been synchronously consumed".to_owned(),
            ));
        }
        match self.committed_sha256 {
            Some(expected_hash) => {
                let installed = read_regular_nofollow(&self.store.main_path())?;
                let installed_counter =
                    read_save_counter(&installed).map_err(VaultStoreError::from_vault)?;
                if installed_counter != self.committed_counter
                    || hash_bytes(&installed) != expected_hash
                {
                    return Err(VaultStoreError::WriterState(
                        "the committed wallet changed outside its authenticated writer".to_owned(),
                    ));
                }
            }
            None => {
                let main = self.store.main_path();
                match fs::symlink_metadata(&main) {
                    Ok(_) => {
                        return Err(VaultStoreError::WriterState(
                            "a wallet file appeared at the new wallet's path; refusing to overwrite it"
                                .to_owned(),
                        ));
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                if !atomic::try_list_temps(&main)?.is_empty()
                    || !atomic::try_list_orphans(&main)?.is_empty()
                {
                    return Err(VaultStoreError::WriterState(
                        "recovery candidates appeared before the first save".to_owned(),
                    ));
                }
            }
        }
        let fresh = self.committed_sha256.is_none();
        let counter = self
            .committed_counter
            .checked_add(1)
            .ok_or_else(|| VaultStoreError::WriterState("save counter overflow".to_owned()))?;
        let mut sections: Vec<(Purpose, &[u8])> =
            vec![(Purpose::Wallet, wallet), (Purpose::Journal, journal)];
        if let Some(activity) = activity {
            sections.push((Purpose::Activity, activity));
        }
        let sealed = vault
            .seal_container(counter, &sections)
            .map_err(VaultStoreError::from_vault)?;
        let target = self.store.main_path();
        let sealed_sha256 = hash_bytes(&sealed);
        self.pending = Some(PendingWrite {
            counter,
            exact_path: target.clone(),
            file_sha256: sealed_sha256,
        });
        Ok(PreparedVaultWrite {
            counter,
            target,
            sealed: Zeroizing::new(sealed),
            sealed_sha256,
            fresh,
        })
    }

    pub fn consume(
        &mut self,
        result: VaultStoreResult<WriteReceipt>,
    ) -> VaultStoreResult<WriteReceipt> {
        let expected = self.pending.take().ok_or_else(|| {
            VaultStoreError::WriterState("no pending write receipt to consume".to_owned())
        })?;
        match result {
            Ok(receipt)
                if receipt.counter == expected.counter
                    && receipt.exact_path == expected.exact_path
                    && receipt.file_sha256 == expected.file_sha256 =>
            {
                self.committed_counter = expected.counter;
                self.committed_sha256 = Some(receipt.file_sha256);
                Ok(receipt)
            }
            Ok(_) => {
                self.healthy = false;
                Err(VaultStoreError::WriterState(
                    "write receipt does not match the reserved counter/path".to_owned(),
                ))
            }
            Err(error) => {
                self.healthy = false;
                Err(error)
            }
        }
    }

    pub fn consume_join_failure(&mut self, detail: impl Into<String>) -> VaultStoreError {
        let detail = detail.into();
        self.pending = None;
        self.healthy = false;
        VaultStoreError::WriterState(format!("started write did not return a receipt: {detail}"))
    }

    pub fn save_sync(
        &mut self,
        vault: &Vault,
        wallet: &[u8],
        journal: &[u8],
        activity: Option<&[u8]>,
    ) -> VaultStoreResult<WriteReceipt> {
        let prepared = self.prepare(vault, wallet, journal, activity)?;
        let result = prepared.execute();
        self.consume(result)
    }
}

pub struct UnlockedVault {
    pub vault: Vault,
    pub wallet: Zeroizing<Vec<u8>>,
    pub journal: Zeroizing<Vec<u8>>,
    pub activity: ActivitySection,
    pub from_newer_container: bool,
    pub selected: SelectedCandidate,
    pub writer: VaultWriter,
}

struct Candidate {
    path: PathBuf,
    counter: u64,
    bytes: Vec<u8>,
    container: OpenedContainer,
}

#[derive(Debug, Clone)]
pub struct VaultStore {
    dir: PathBuf,
    name: String,
}

fn open_candidate_reusing_keyslot(
    bytes: &[u8],
    password: &[u8],
    cached: &mut Vec<cc_wallet_vault::OpenedKeyslot>,
) -> Result<cc_wallet_vault::OpenedContainer, VaultError> {
    for slot in cached.iter() {
        match Vault::open_container_with(bytes, slot) {
            Ok(container) => return Ok(container),
            Err(VaultError::WrongPassword) => continue,
            Err(other) => return Err(other),
        }
    }
    let slot = Vault::open_keyslot(bytes, password)?;
    let container = Vault::open_container_with(bytes, &slot)?;
    cached.push(slot);
    Ok(container)
}

impl VaultStore {
    pub fn new(dir: impl Into<PathBuf>, name: impl Into<String>) -> Self {
        Self {
            dir: dir.into(),
            name: name.into(),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn main_path(&self) -> PathBuf {
        self.dir.join(main_file(&self.name))
    }

    pub fn read_display_name(&self) -> VaultStoreResult<Option<String>> {
        validate_wallet_name(&self.name)?;
        let main = self.main_path();
        match fs::symlink_metadata(&main) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || has_multiple_links(&metadata)
                {
                    return Err(VaultStoreError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "wallet path is not a singly-linked regular file: {}",
                            absolute(&main).display()
                        ),
                    )));
                }
                let (prefix, _) =
                    read_prefix_nofollow(&main, cc_wallet_vault::MAX_HEADER_PROBE_LEN)?;
                return Ok(cc_wallet_vault::read_display_name(&prefix)
                    .ok()
                    .map(str::to_owned));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(VaultStoreError::Io(error)),
        }

        let mut display_name: Option<String> = None;
        for path in atomic::try_list_temps(&main)?
            .into_iter()
            .chain(atomic::try_list_orphans(&main)?)
        {
            let (prefix, file_len) =
                match read_prefix_nofollow(&path, cc_wallet_vault::MAX_HEADER_PROBE_LEN) {
                    Ok(read) => read,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(VaultStoreError::Io(error)),
                };
            if cc_wallet_vault::container_declared_len(&prefix) != Some(file_len) {
                continue;
            }
            let label =
                cc_wallet_vault::read_display_name(&prefix).map_err(VaultStoreError::from_vault)?;
            if display_name.as_deref().is_some_and(|known| known != label) {
                return Err(VaultStoreError::Vault(VaultError::Corrupt(
                    "recovery candidates carry different wallet display names",
                )));
            }
            display_name = Some(label.to_owned());
        }
        Ok(display_name)
    }

    pub fn writer_for_new(&self) -> VaultStoreResult<VaultWriter> {
        validate_wallet_name(&self.name)?;
        VaultWriter::fresh(self.clone())
    }

    pub fn exists(&self) -> VaultStoreResult<bool> {
        validate_wallet_name(&self.name)?;
        let main = self.main_path();
        match fs::symlink_metadata(&main) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                return Ok(true);
            }
            Ok(_) => {
                return Err(VaultStoreError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "wallet path is not a regular no-follow file: {}",
                        absolute(&main).display()
                    ),
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(VaultStoreError::Io(io_at_path(
                    "reading wallet metadata at",
                    &main,
                    error,
                )));
            }
        }
        for path in atomic::try_list_temps(&main)?
            .into_iter()
            .chain(atomic::try_list_orphans(&main)?)
        {
            match is_container_by_header(&path) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(VaultStoreError::Io(error)),
            }
        }
        Ok(false)
    }

    pub fn unlock(&self, password: &[u8]) -> VaultStoreResult<UnlockedVault> {
        validate_wallet_name(&self.name)?;
        let main = self.main_path();
        let main_present = match fs::symlink_metadata(&main) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(VaultStoreError::Io(error)),
        };
        let mut candidate_paths: Vec<PathBuf> = Vec::new();
        if main_present {
            candidate_paths.push(main.clone());
        }
        candidate_paths.extend(atomic::try_list_temps(&main)?);
        candidate_paths.extend(atomic::try_list_orphans(&main)?);

        let mut opened: Vec<Candidate> = Vec::new();
        let mut first_err: Option<VaultError> = None;
        let mut main_authenticated = false;
        let mut plausible_keyslots: Vec<Vec<u8>> = Vec::new();
        let mut cached_keyslots: Vec<cc_wallet_vault::OpenedKeyslot> = Vec::new();
        for path in candidate_paths {
            let is_main = path == main;
            if !is_main {
                match read_prefix_nofollow(&path, cc_wallet_vault::MAX_HEADER_PROBE_LEN) {
                    Ok((prefix, file_len)) => {
                        if file_len > MAX_CANDIDATE_CONTAINER_BYTES {
                            continue;
                        }
                        if let Ok(params) = cc_wallet_vault::read_kdf_params(&prefix)
                            && cc_wallet_vault::KdfParams::DEFAULT.weaker_than(params)
                        {
                            continue;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(VaultStoreError::Io(error)),
                }
            }
            let bytes = match read_regular_nofollow(&path) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(VaultStoreError::Io(error)),
            };
            if cc_wallet_vault::looks_like_container(&bytes)
                && let Some(keyslot) = cc_wallet_vault::keyslot_prefix(&bytes)
            {
                plausible_keyslots.push(keyslot.to_vec());
            }
            match open_candidate_reusing_keyslot(&bytes, password, &mut cached_keyslots) {
                Ok(container) => {
                    if is_main {
                        main_authenticated = true;
                    }
                    opened.push(Candidate {
                        path,
                        counter: container.save_counter,
                        bytes,
                        container,
                    });
                }
                Err(error) => {
                    first_err.get_or_insert(error);
                }
            }
        }

        if main_present && !main_authenticated {
            return Err(VaultStoreError::from_vault(
                first_err.unwrap_or(VaultError::WrongPassword),
            ));
        }

        if main_authenticated {
            if let Some(main_keyslot) = opened
                .iter()
                .find(|candidate| candidate.path == main)
                .and_then(|candidate| cc_wallet_vault::keyslot_prefix(&candidate.bytes))
                .map(<[u8]>::to_vec)
            {
                opened.retain(|candidate| {
                    candidate.path == main
                        || cc_wallet_vault::keyslot_prefix(&candidate.bytes)
                            == Some(main_keyslot.as_slice())
                });
            }
        } else if plausible_keyslots.windows(2).any(|pair| pair[0] != pair[1]) {
            return Err(VaultStoreError::Vault(VaultError::Corrupt(
                "ambiguous recovery: candidates span different key generations",
            )));
        }

        if opened.is_empty() {
            return Err(match first_err {
                Some(error) => VaultStoreError::from_vault(error),
                None => VaultStoreError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no wallet file to open",
                )),
            });
        }

        let top = opened
            .iter()
            .map(|c| c.counter)
            .max()
            .expect("opened is non-empty");
        let winner_idx = opened
            .iter()
            .position(|c| c.counter == top)
            .expect("a candidate at the top counter exists");
        let ambiguous = opened.iter().enumerate().any(|(i, c)| {
            i != winner_idx && c.counter == top && c.bytes != opened[winner_idx].bytes
        });
        if ambiguous {
            return Err(VaultStoreError::Vault(VaultError::Corrupt(
                "ambiguous recovery: two authenticated saves share the newest counter",
            )));
        }

        let winner_path = opened[winner_idx].path.clone();
        let promoted = winner_path != main;
        if promoted {
            atomic::write_atomic(&main, &opened[winner_idx].bytes)?;
        }

        let selected = SelectedCandidate {
            owner_main: main.clone(),
            path: if promoted {
                main.clone()
            } else {
                winner_path.clone()
            },
            counter: opened[winner_idx].counter,
            sha256: hash_bytes(&opened[winner_idx].bytes),
        };
        let writer = VaultWriter::authenticated(self.clone(), &selected)?;

        if promoted
            && winner_path
                .extension()
                .is_some_and(|extension| extension == "tmp")
        {
            let _ = fs::remove_file(&winner_path);
        }

        let Candidate { container, .. } = opened.swap_remove(winner_idx);
        Ok(UnlockedVault {
            vault: container.vault,
            wallet: container.wallet,
            journal: container.journal,
            activity: container.activity,
            from_newer_container: container.has_unknown_sections,
            selected,
            writer,
        })
    }

    fn orphan_path(&self, counter: u64) -> PathBuf {
        self.dir
            .join(format!("{}.v1.{counter}.orphan", main_file(&self.name)))
    }

    pub fn quarantine_selected(&self, selected: &SelectedCandidate) -> VaultStoreResult<PathBuf> {
        if selected.owner_main != self.main_path() {
            return Err(VaultStoreError::WriterState(
                "selected quarantine candidate belongs to a different wallet path".to_owned(),
            ));
        }
        let source = read_regular_nofollow(&selected.path)?;
        if hash_bytes(&source) != selected.sha256 {
            return Err(VaultStoreError::Vault(VaultError::Corrupt(
                "selected candidate changed before quarantine",
            )));
        }
        let orphan = self.orphan_path(selected.counter);
        atomic::install_orphan_copy(&orphan, &source)?;
        let installed = read_regular_nofollow(&orphan)?;
        let source_after = read_regular_nofollow(&selected.path)?;
        if installed != source
            || source_after != source
            || hash_bytes(&source_after) != selected.sha256
        {
            return Err(VaultStoreError::Vault(VaultError::Corrupt(
                "selected candidate changed while its quarantine copy was installed",
            )));
        }
        Ok(orphan)
    }

    pub fn shred_foreign_keyslot_residue(&self) -> VaultStoreResult<Vec<PathBuf>> {
        validate_wallet_name(&self.name)?;
        let main = self.main_path();
        let (main_prefix, _) = read_prefix_nofollow(&main, cc_wallet_vault::MAX_HEADER_PROBE_LEN)?;
        let main_keyslot = cc_wallet_vault::keyslot_prefix(&main_prefix)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                VaultStoreError::WriterState(
                    "current wallet keyslot is unreadable; refusing to scope residue shredding"
                        .to_owned(),
                )
            })?;

        let mut shredded = Vec::new();
        for path in atomic::try_list_temps(&main)?
            .into_iter()
            .chain(atomic::try_list_orphans(&main)?)
        {
            let (prefix, _) =
                match read_prefix_nofollow(&path, cc_wallet_vault::MAX_HEADER_PROBE_LEN) {
                    Ok(read) => read,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(VaultStoreError::Io(error)),
                };
            if cc_wallet_vault::container_declared_len(&prefix).is_none() {
                continue;
            }
            match cc_wallet_vault::keyslot_prefix(&prefix) {
                Some(candidate) if candidate != main_keyslot.as_slice() => {}
                _ => continue,
            }
            let kind = if path
                .extension()
                .is_some_and(|extension| extension == "orphan")
            {
                DestroyArtifactKind::QuarantineOrphan
            } else {
                DestroyArtifactKind::Temporary
            };
            match destroy_artifact(&path, kind) {
                Ok(_) => shredded.push(path),
                Err((operation, source, _)) => {
                    return Err(VaultStoreError::Io(io_at_path(operation, &path, source)));
                }
            }
        }
        Ok(shredded)
    }

    pub fn read_wallet(&self, vault: &Vault) -> VaultStoreResult<Zeroizing<Vec<u8>>> {
        let bytes = read_regular_nofollow(&self.main_path())?;
        vault
            .read_section(Purpose::Wallet, &bytes)
            .map_err(VaultStoreError::from_vault)?
            .ok_or(VaultStoreError::Vault(VaultError::Corrupt(
                "wallet section missing",
            )))
    }

    pub fn destroy(&self) -> Result<DestroyReport, DestroyError> {
        let main = self.main_path();
        if let Err(error) = validate_wallet_name(&self.name) {
            return Err(DestroyError {
                operation: "validating the wallet name for",
                path: absolute(&self.dir),
                source: io::Error::new(io::ErrorKind::InvalidInput, error.to_string()),
                report: Box::new(DestroyReport {
                    artifacts: Vec::new(),
                    residues: vec![absolute(&main)],
                    active_lock: None,
                }),
                residue_scan_error: None,
            });
        }
        let active_lock = visible_lock(&self.dir).map_err(|source| DestroyError {
            operation: "enumerating directory lock at",
            path: absolute(&self.dir.join(crate::paths::LOCK_FILE)),
            source,
            report: Box::new(DestroyReport {
                artifacts: Vec::new(),
                residues: vec![absolute(&main)],
                active_lock: None,
            }),
            residue_scan_error: None,
        })?;
        let candidates = self.destroy_candidates().map_err(|source| DestroyError {
            operation: "enumerating wallet ciphertext at",
            path: absolute(&main),
            source,
            report: Box::new(DestroyReport {
                artifacts: Vec::new(),
                residues: vec![absolute(&main)],
                active_lock: active_lock.clone(),
            }),
            residue_scan_error: None,
        })?;
        let mut artifacts = Vec::with_capacity(candidates.len());
        for (path, kind) in candidates {
            match destroy_artifact(&path, kind) {
                Ok(outcome) => artifacts.push(outcome),
                Err((operation, source, outcome)) => {
                    artifacts.push(outcome);
                    return Err(self.destroy_error(
                        operation,
                        &path,
                        source,
                        artifacts,
                        active_lock,
                    ));
                }
            }
        }
        let residues = match self.visible_ciphertext() {
            Ok(residues) => residues,
            Err(source) => {
                return Err(self.destroy_error(
                    "verifying wallet ciphertext removal at",
                    &main,
                    source,
                    artifacts,
                    active_lock,
                ));
            }
        };
        let report = DestroyReport {
            artifacts,
            residues,
            active_lock,
        };
        if report.residues.is_empty() {
            Ok(report)
        } else {
            Err(DestroyError {
                operation: "verifying wallet ciphertext removal at",
                path: absolute(&main),
                source: io::Error::other("one or more encrypted wallet artifacts remain"),
                report: Box::new(report),
                residue_scan_error: None,
            })
        }
    }

    fn destroy_candidates(&self) -> io::Result<Vec<(PathBuf, DestroyArtifactKind)>> {
        let main = self.main_path();
        let mut candidates = Vec::new();
        match fs::symlink_metadata(&main) {
            Ok(_) => candidates.push((main.clone(), DestroyArtifactKind::Main)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        candidates.extend(
            atomic::try_list_temps(&main)?
                .into_iter()
                .map(|path| (path, DestroyArtifactKind::Temporary)),
        );
        candidates.extend(
            atomic::try_list_orphans(&main)?
                .into_iter()
                .map(|path| (path, DestroyArtifactKind::QuarantineOrphan)),
        );
        candidates.sort_by(|left, right| left.0.cmp(&right.0));
        candidates.dedup_by(|left, right| left.0 == right.0);
        Ok(candidates)
    }

    fn visible_ciphertext(&self) -> io::Result<Vec<PathBuf>> {
        Ok(self
            .destroy_candidates()?
            .into_iter()
            .map(|(path, _)| absolute(&path))
            .collect())
    }

    fn destroy_error(
        &self,
        operation: &'static str,
        path: &Path,
        source: io::Error,
        artifacts: Vec<DestroyArtifactOutcome>,
        active_lock: Option<PathBuf>,
    ) -> DestroyError {
        let (residues, residue_scan_error) = match self.visible_ciphertext() {
            Ok(residues) => (residues, None),
            Err(error) => {
                let known = self
                    .destroy_candidates()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(path, _)| absolute(&path))
                    .collect();
                (known, Some(error.to_string()))
            }
        };
        DestroyError {
            operation,
            path: absolute(path),
            source,
            report: Box::new(DestroyReport {
                artifacts,
                residues,
                active_lock,
            }),
            residue_scan_error,
        }
    }
}

fn absolute(path: &Path) -> PathBuf {
    path.to_path_buf()
}

fn visible_lock(dir: &Path) -> io::Result<Option<PathBuf>> {
    let path = dir.join(crate::paths::LOCK_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => Ok(Some(absolute(&path))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn metadata_identity(metadata: &fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

#[cfg(unix)]
fn has_multiple_links(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink() != 1
}

#[cfg(not(unix))]
fn has_multiple_links(_metadata: &fs::Metadata) -> bool {
    false
}

fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        metadata_identity(left) == metadata_identity(right)
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len() && left.file_type() == right.file_type()
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    #[cfg(unix)]
    {
        fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

type DestroyArtifactError = (&'static str, io::Error, DestroyArtifactOutcome);

fn destroy_artifact(
    path: &Path,
    kind: DestroyArtifactKind,
) -> Result<DestroyArtifactOutcome, DestroyArtifactError> {
    let initial = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return Err((
                "reading wallet artifact metadata at",
                error,
                DestroyArtifactOutcome {
                    path: absolute(path),
                    kind,
                    overwrite: OverwriteOutcome::Incomplete { bytes: 0 },
                    unlinked: false,
                    directory_synced: false,
                },
            ));
        }
    };
    if initial.file_type().is_symlink() {
        let mut outcome = DestroyArtifactOutcome {
            path: absolute(path),
            kind,
            overwrite: OverwriteOutcome::SkippedSymlink,
            unlinked: false,
            directory_synced: false,
        };
        let current = fs::symlink_metadata(path)
            .map_err(|error| ("rechecking wallet symlink at", error, outcome.clone()))?;
        if !current.file_type().is_symlink() || !same_identity(&initial, &current) {
            return Err((
                "validating wallet symlink identity at",
                io::Error::other("artifact changed during destruction"),
                outcome,
            ));
        }
        fs::remove_file(path)
            .map_err(|error| ("unlinking wallet symlink at", error, outcome.clone()))?;
        outcome.unlinked = true;
        sync_parent(path).map_err(|error| {
            (
                "syncing wallet directory after unlink at",
                error,
                outcome.clone(),
            )
        })?;
        outcome.directory_synced = true;
        return Ok(outcome);
    }
    if !initial.is_file() || has_multiple_links(&initial) {
        let outcome = DestroyArtifactOutcome {
            path: absolute(path),
            kind,
            overwrite: OverwriteOutcome::UnsupportedFileType,
            unlinked: false,
            directory_synced: false,
        };
        return Err((
            "refusing non-regular or hard-linked wallet artifact at",
            io::Error::other("artifact is not a singly-linked regular file"),
            outcome,
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|error| {
        (
            "opening wallet artifact without following links at",
            error,
            DestroyArtifactOutcome {
                path: absolute(path),
                kind,
                overwrite: OverwriteOutcome::Incomplete { bytes: 0 },
                unlinked: false,
                directory_synced: false,
            },
        )
    })?;
    let opened = file.metadata().map_err(|error| {
        (
            "reading opened wallet artifact metadata at",
            error,
            DestroyArtifactOutcome {
                path: absolute(path),
                kind,
                overwrite: OverwriteOutcome::Incomplete { bytes: 0 },
                unlinked: false,
                directory_synced: false,
            },
        )
    })?;
    if !same_identity(&initial, &opened) {
        return Err((
            "validating opened wallet artifact identity at",
            io::Error::other("artifact changed before no-follow open"),
            DestroyArtifactOutcome {
                path: absolute(path),
                kind,
                overwrite: OverwriteOutcome::Incomplete { bytes: 0 },
                unlinked: false,
                directory_synced: false,
            },
        ));
    }

    let zeros = [0u8; 4096];
    let mut written = 0u64;
    while written < opened.len() {
        let chunk = (opened.len() - written).min(zeros.len() as u64) as usize;
        if let Err(error) = file.write_all(&zeros[..chunk]) {
            return Err((
                "overwriting wallet artifact at",
                error,
                DestroyArtifactOutcome {
                    path: absolute(path),
                    kind,
                    overwrite: OverwriteOutcome::Incomplete { bytes: written },
                    unlinked: false,
                    directory_synced: false,
                },
            ));
        }
        written += chunk as u64;
    }
    let incomplete = || DestroyArtifactOutcome {
        path: absolute(path),
        kind,
        overwrite: OverwriteOutcome::Incomplete { bytes: written },
        unlinked: false,
        directory_synced: false,
    };
    file.sync_all().map_err(|error| {
        (
            "syncing overwritten wallet artifact at",
            error,
            incomplete(),
        )
    })?;
    file.rewind().map_err(|error| {
        (
            "seeking overwritten wallet artifact at",
            error,
            incomplete(),
        )
    })?;
    let mut verify = vec![0u8; zeros.len()];
    let mut remaining = opened.len();
    while remaining > 0 {
        let chunk = remaining.min(verify.len() as u64) as usize;
        use std::io::Read;
        file.read_exact(&mut verify[..chunk]).map_err(|error| {
            (
                "verifying overwritten wallet artifact at",
                error,
                incomplete(),
            )
        })?;
        if verify[..chunk].iter().any(|byte| *byte != 0) {
            return Err((
                "verifying overwritten wallet artifact at",
                io::Error::other("overwrite readback was not all zero"),
                incomplete(),
            ));
        }
        remaining -= chunk as u64;
    }
    let current = fs::symlink_metadata(path).map_err(|error| {
        (
            "rechecking overwritten wallet artifact at",
            error,
            incomplete(),
        )
    })?;
    if !same_identity(&opened, &current) {
        return Err((
            "validating overwritten wallet artifact identity at",
            io::Error::other("artifact changed before unlink"),
            incomplete(),
        ));
    }
    let mut outcome = DestroyArtifactOutcome {
        path: absolute(path),
        kind,
        overwrite: OverwriteOutcome::Completed {
            bytes: opened.len(),
        },
        unlinked: false,
        directory_synced: false,
    };
    fs::remove_file(path).map_err(|error| {
        (
            "unlinking overwritten wallet artifact at",
            error,
            outcome.clone(),
        )
    })?;
    outcome.unlinked = true;
    sync_parent(path).map_err(|error| {
        (
            "syncing wallet directory after unlink at",
            error,
            outcome.clone(),
        )
    })?;
    outcome.directory_synced = true;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_wallet_vault::KdfParams;

    const CHEAP: KdfParams = KdfParams {
        m_kib: 32,
        t: 2,
        p: 1,
    };
    const PW: &[u8] = b"unlock me please";
    const PROFILE: &[u8] = b"{\"seed\":\"a b c\",\"endpoint\":\"http://x\"}";
    const JOURNAL: &[u8] = b"{\"schema_version\":1,\"records\":[]}";
    const HISTORY: &[u8] = b"[{\"lt\":7}]";
    const EMPTY_HISTORY: &[u8] = b"[]";

    fn alice_store() -> (tempfile::TempDir, VaultStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path(), "alice");
        (dir, store)
    }

    fn store() -> (tempfile::TempDir, VaultStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path(), DEFAULT_WALLET_NAME);
        (dir, store)
    }

    fn save_new(
        store: &VaultStore,
        vault: &Vault,
        wallet: &[u8],
        journal: &[u8],
        activity: Option<&[u8]>,
    ) -> VaultWriter {
        let mut writer = store.writer_for_new().unwrap();
        writer.save_sync(vault, wallet, journal, activity).unwrap();
        writer
    }

    fn sealed_next(
        writer: &mut VaultWriter,
        vault: &Vault,
        wallet: &[u8],
        journal: &[u8],
        activity: Option<&[u8]>,
    ) -> Vec<u8> {
        writer
            .prepare(vault, wallet, journal, activity)
            .unwrap()
            .sealed
            .to_vec()
    }

    #[test]
    fn list_wallets_finds_names_and_ignores_temps() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        for name in ["alice", "bob"] {
            save_new(
                &VaultStore::new(dir.path(), name),
                &vault,
                PROFILE,
                JOURNAL,
                Some(HISTORY),
            );
        }
        fs::write(dir.path().join("alice.ccwallet.zz.tmp"), b"x").unwrap();
        assert_eq!(list_wallets(dir.path()).unwrap(), vec!["alice", "bob"]);
    }

    fn survivor_only(dir: &Path, stem: &str, vault: &Vault) {
        let store = VaultStore::new(dir, stem);
        save_new(&store, vault, PROFILE, JOURNAL, Some(HISTORY));
        let bytes = fs::read(store.main_path()).unwrap();
        fs::write(dir.join(format!("{stem}.ccwallet.zz.tmp")), &bytes).unwrap();
        fs::remove_file(store.main_path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn discovery_ignores_a_huge_garbage_residue_without_reading_it() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(
            &VaultStore::new(dir.path(), "alice"),
            &vault,
            PROFILE,
            JOURNAL,
            Some(HISTORY),
        );

        let residue = dir.path().join("huge.ccwallet.zz.tmp");
        let file = fs::File::create(&residue).unwrap();
        file.set_len(8 * 1024 * 1024 * 1024).unwrap();

        assert_eq!(list_wallets(dir.path()).unwrap(), vec!["alice"]);
        let huge = VaultStore::new(dir.path(), "huge");
        assert!(!huge.exists().unwrap());
        assert_eq!(huge.read_display_name().unwrap(), None);
    }

    #[test]
    fn a_container_copied_to_a_tmp_is_still_discovered() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create_named_with(PW, CHEAP, "Survivor Label").unwrap();
        survivor_only(dir.path(), "survivor", &vault);

        let store = VaultStore::new(dir.path(), "survivor");
        assert!(
            store.exists().unwrap(),
            "a complete survivor container is discovered by the bounded probe"
        );
        assert_eq!(list_wallets(dir.path()).unwrap(), vec!["survivor"]);
        assert_eq!(
            store.read_display_name().unwrap().as_deref(),
            Some("Survivor Label")
        );
    }

    #[test]
    fn a_large_survivor_container_is_discovered_by_the_bounded_probe() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create_named_with(PW, CHEAP, "Big Wallet").unwrap();
        let store = VaultStore::new(dir.path(), "big");
        let big_history = vec![b'x'; 16 * 1024];
        save_new(&store, &vault, PROFILE, JOURNAL, Some(&big_history));
        let bytes = fs::read(store.main_path()).unwrap();
        assert!(bytes.len() > cc_wallet_vault::MAX_HEADER_PROBE_LEN);
        fs::write(dir.path().join("big.ccwallet.zz.tmp"), &bytes).unwrap();
        fs::remove_file(store.main_path()).unwrap();

        assert!(store.exists().unwrap());
        assert_eq!(list_wallets(dir.path()).unwrap(), vec!["big"]);
        assert_eq!(
            store.read_display_name().unwrap().as_deref(),
            Some("Big Wallet")
        );
    }

    #[test]
    fn a_container_with_trailing_junk_is_rejected_by_the_probe() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        let store = VaultStore::new(dir.path(), "padded");
        save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        let mut bytes = fs::read(store.main_path()).unwrap();
        fs::remove_file(store.main_path()).unwrap();
        bytes.push(0);
        fs::write(dir.path().join("padded.ccwallet.zz.tmp"), &bytes).unwrap();

        assert!(!store.exists().unwrap());
        assert!(list_wallets(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn wallet_listing_keeps_the_slug_storage_id_and_exact_display_name() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path(), "my-ton-wallet");
        let vault = Vault::create_named_with(PW, CHEAP, "My TON Wallet").unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));

        assert_eq!(
            store.main_path().file_name().and_then(|name| name.to_str()),
            Some("my-ton-wallet.ccwallet")
        );
        assert_eq!(
            store.read_display_name().unwrap().as_deref(),
            Some("My TON Wallet")
        );
        assert_eq!(
            list_wallet_entries(dir.path()).unwrap(),
            vec![WalletListing {
                storage_id: "my-ton-wallet".to_owned(),
                display_name: "My TON Wallet".to_owned(),
            }]
        );
    }

    #[test]
    fn an_unsupported_container_listing_falls_back_to_its_storage_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path(), "legacy-wallet");
        let vault = Vault::create_named_with(PW, CHEAP, "Legacy Wallet").unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));

        let mut unsupported = fs::read(store.main_path()).unwrap();
        unsupported[8..10].copy_from_slice(&2u16.to_le_bytes());
        fs::write(store.main_path(), unsupported).unwrap();

        assert_eq!(store.read_display_name().unwrap(), None);
        assert_eq!(
            list_wallet_entries(dir.path()).unwrap(),
            vec![WalletListing {
                storage_id: "legacy-wallet".to_owned(),
                display_name: "legacy-wallet".to_owned(),
            }]
        );
    }

    #[cfg(unix)]
    #[test]
    fn wallet_discovery_lists_a_symlink_but_reads_refuse_to_follow_it() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("outside-wallet");
        fs::write(&target, b"not in the wallet root").unwrap();
        let link = dir.path().join("alice.ccwallet");
        symlink(&target, &link).unwrap();

        assert_eq!(list_wallets(dir.path()).unwrap(), vec!["alice".to_owned()]);
        let store = VaultStore::new(dir.path(), "alice");
        assert!(store.exists().is_err());
        assert!(store.unlock(PW).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"not in the wallet root");
    }

    #[test]
    fn an_alien_entry_does_not_fail_the_whole_listing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(
            &VaultStore::new(dir.path(), "alice"),
            &vault,
            PROFILE,
            JOURNAL,
            Some(HISTORY),
        );
        fs::create_dir(dir.path().join("old.ccwallet")).unwrap();

        let entries = list_wallet_entries(dir.path()).unwrap();
        let ids: Vec<&str> = entries.iter().map(|e| e.storage_id.as_str()).collect();
        assert!(ids.contains(&"alice"), "the healthy wallet is still listed");
        assert!(
            ids.contains(&"old"),
            "the alien entry appears under its filename stem"
        );
        assert!(VaultStore::new(dir.path(), "alice").unlock(PW).is_ok());
        assert!(VaultStore::new(dir.path(), "old").unlock(PW).is_err());
    }

    #[test]
    fn store_operations_reject_escaping_and_aliasing_names() {
        let dir = tempfile::tempdir().unwrap();
        for bad in [
            "../elsewhere/w",
            "a/b",
            "a\\b",
            "..",
            ".",
            "",
            "alice.ccwallet",
            "x.CCWALLET.y",
        ] {
            let store = VaultStore::new(dir.path(), bad);
            assert!(store.exists().is_err(), "exists must reject {bad:?}");
            assert!(
                store.writer_for_new().is_err(),
                "writer_for_new must reject {bad:?}"
            );
            assert!(store.unlock(PW).is_err(), "unlock must reject {bad:?}");
            assert!(store.destroy().is_err(), "destroy must reject {bad:?}");
        }
        for good in ["alice", "my-ton-wallet"] {
            let store = VaultStore::new(dir.path(), good);
            assert!(store.exists().is_ok(), "a valid name is accepted: {good:?}");
        }
    }

    #[test]
    fn listing_skips_an_aliasing_stem() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(
            &VaultStore::new(dir.path(), "alice"),
            &vault,
            PROFILE,
            JOURNAL,
            Some(HISTORY),
        );
        fs::write(dir.path().join("alice.ccwallet.ccwallet"), b"junk").unwrap();

        let ids = list_wallets(dir.path()).unwrap();
        assert_eq!(
            ids,
            vec!["alice".to_owned()],
            "the aliasing stem is skipped"
        );
    }

    #[test]
    fn two_wallets_in_one_dir_are_independent() {
        let dir = tempfile::tempdir().unwrap();
        let a = VaultStore::new(dir.path(), "alice");
        let b = VaultStore::new(dir.path(), "bob");
        save_new(
            &a,
            &Vault::create_with(b"aaaaaaaa", CHEAP).unwrap(),
            b"A",
            JOURNAL,
            Some(EMPTY_HISTORY),
        );
        save_new(
            &b,
            &Vault::create_with(b"bbbbbbbb", CHEAP).unwrap(),
            b"B",
            JOURNAL,
            Some(EMPTY_HISTORY),
        );
        assert_eq!(&a.unlock(b"aaaaaaaa").unwrap().wallet[..], b"A");
        assert_eq!(&b.unlock(b"bbbbbbbb").unwrap().wallet[..], b"B");
        match a.unlock(b"bbbbbbbb") {
            Err(error) => assert!(error.is_wrong_password()),
            Ok(_) => panic!("bob's password opened alice's wallet"),
        }
    }

    #[test]
    fn create_save_unlock_round_trip() {
        let (_d, store) = store();
        assert!(!store.exists().unwrap());
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        assert!(store.exists().unwrap());

        let opened = store.unlock(PW).unwrap();
        assert_eq!(&opened.wallet[..], PROFILE);
        assert!(
            matches!(opened.activity, ActivitySection::Present(h) if &h[..] == HISTORY),
            "the saved history round-trips as Present"
        );
    }

    #[test]
    fn rekey_residue_shred_removes_old_keyslot_copies_and_keeps_the_new_main() {
        let (_dir, store) = store();
        let vault_old = Vault::create_with(PW, CHEAP).unwrap();
        save_new(&store, &vault_old, PROFILE, JOURNAL, Some(HISTORY));
        let opened = store.unlock(PW).unwrap();
        let orphan = store.quarantine_selected(&opened.selected).unwrap();
        assert!(orphan.exists(), "an old-keyslot quarantine copy exists");
        assert!(Vault::open_container(&fs::read(&orphan).unwrap(), PW).is_ok());

        let vault_new = Vault::create_with(b"new-password", CHEAP).unwrap();
        let sealed_new = vault_new
            .seal_container(
                1,
                &[(Purpose::Wallet, PROFILE), (Purpose::Journal, JOURNAL)],
            )
            .unwrap();
        atomic::write_atomic(&store.main_path(), &sealed_new).unwrap();

        let shredded = store.shred_foreign_keyslot_residue().unwrap();
        assert_eq!(
            shredded.len(),
            1,
            "exactly the old-keyslot orphan is shredded"
        );
        assert!(!orphan.exists(), "the old-password copy is gone");
        assert!(store.main_path().exists(), "the new-keyslot main survives");
        assert!(
            store.unlock(b"new-password").is_ok(),
            "main still opens with the new password"
        );
        match store.unlock(PW) {
            Err(error) => assert!(error.is_wrong_password()),
            Ok(_) => panic!("the old password must not open the new main"),
        }
    }

    #[test]
    fn unlock_skips_oversized_and_high_kdf_planted_candidates() {
        let (dir, store) = alice_store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));

        fs::File::create(dir.path().join("alice.ccwallet.zz.tmp"))
            .unwrap()
            .set_len(200 * 1024 * 1024)
            .unwrap();

        let mut high_kdf = fs::read(store.main_path()).unwrap();
        high_kdf[11..15].copy_from_slice(&1_048_576u32.to_le_bytes());
        high_kdf[15..19].copy_from_slice(&16u32.to_le_bytes());
        fs::write(dir.path().join("alice.ccwallet.yy.tmp"), &high_kdf).unwrap();
        assert!(
            cc_wallet_vault::KdfParams::DEFAULT
                .weaker_than(cc_wallet_vault::read_kdf_params(&high_kdf).unwrap()),
            "the planted header really advertises out-of-policy KDF params"
        );

        let opened = store.unlock(PW).unwrap();
        assert_eq!(&opened.wallet[..], PROFILE);
    }

    #[test]
    fn the_writer_allows_one_pending_counter_and_requires_its_exact_receipt() {
        let (_dir, store) = store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        let mut writer = store.writer_for_new().unwrap();
        let prepared = writer
            .prepare(&vault, PROFILE, JOURNAL, Some(HISTORY))
            .unwrap();
        assert_eq!(prepared.save_counter(), 1);
        assert!(
            writer
                .prepare(&vault, PROFILE, JOURNAL, Some(HISTORY))
                .is_err(),
            "a second counter cannot be reserved before the first receipt"
        );
        let receipt = prepared.execute().unwrap();
        assert_eq!(receipt.save_counter(), 1);
        assert_eq!(receipt.exact_path(), store.main_path());
        assert_eq!(
            receipt.file_sha256(),
            &hash_bytes(&fs::read(store.main_path()).unwrap())
        );
        writer.consume(Ok(receipt)).unwrap();
        assert_eq!(writer.committed_counter(), 1);
        assert!(writer.is_healthy());
    }

    #[test]
    fn a_receipt_for_different_prepared_bytes_cannot_advance_the_writer() {
        let (_dir, store) = store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        let mut expected_writer = store.writer_for_new().unwrap();
        let mut other_writer = store.writer_for_new().unwrap();
        let expected = expected_writer
            .prepare(&vault, b"expected", JOURNAL, Some(HISTORY))
            .unwrap();
        let other = other_writer
            .prepare(&vault, b"different", JOURNAL, Some(HISTORY))
            .unwrap();
        assert_eq!(expected.save_counter(), other.save_counter());

        let other_receipt = other.execute().unwrap();
        let error = expected_writer.consume(Ok(other_receipt)).unwrap_err();
        assert!(error.to_string().contains("does not match"));
        assert!(!expected_writer.is_healthy());
        assert!(
            expected_writer
                .prepare(&vault, b"later", JOURNAL, Some(HISTORY))
                .is_err(),
            "a mismatched receipt permanently poisons the counter owner"
        );
    }

    #[test]
    fn an_uncertain_write_failure_poisons_the_writer_permanently() {
        let (_dir, store) = store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        let mut writer = store.writer_for_new().unwrap();
        let _prepared = writer
            .prepare(&vault, PROFILE, JOURNAL, Some(HISTORY))
            .unwrap();
        assert!(
            writer
                .consume(Err(VaultStoreError::Io(io::Error::other(
                    "injected durability failure",
                ))))
                .is_err()
        );
        assert!(!writer.is_healthy());
        assert!(
            writer
                .prepare(&vault, PROFILE, JOURNAL, Some(HISTORY))
                .is_err(),
            "a failed started write cannot be retried under a guessed counter"
        );
    }

    #[test]
    fn a_stale_authenticated_writer_cannot_commit_after_a_newer_writer() {
        let (_dir, store) = store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        let mut first = store.unlock(PW).unwrap().writer;
        let mut stale = store.unlock(PW).unwrap().writer;
        first
            .save_sync(&vault, b"newest", JOURNAL, Some(HISTORY))
            .unwrap();
        assert!(
            stale
                .prepare(&vault, b"stale", JOURNAL, Some(HISTORY))
                .is_err(),
            "the old writer's bound main hash refuses a stale overwrite"
        );
        assert_eq!(&store.unlock(PW).unwrap().wallet[..], b"newest");
    }

    #[test]
    fn a_corrupt_activity_section_unlocks_as_corrupt() {
        let (_d, store) = store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        let path = store.main_path();
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(&path, &bytes).unwrap();

        let opened = store.unlock(PW).unwrap();
        assert_eq!(
            &opened.wallet[..],
            PROFILE,
            "the wallet section still opens"
        );
        assert!(
            matches!(opened.activity, ActivitySection::Corrupt),
            "the damaged activity section is reported Corrupt"
        );
    }

    fn store_with_corrupt_activity(dir: &Path, name: &str) -> (VaultStore, Vec<u8>) {
        let store = VaultStore::new(dir, name);
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        let path = store.main_path();
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        (store, bytes)
    }

    #[test]
    fn quarantine_copies_the_selected_bytes_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let (store, main_bytes) = store_with_corrupt_activity(dir.path(), "alice");
        let opened = store.unlock(PW).unwrap();
        assert!(matches!(opened.activity, ActivitySection::Corrupt));

        let orphan = store.quarantine_selected(&opened.selected).unwrap();
        assert!(orphan.to_string_lossy().ends_with(".v1.1.orphan"));
        assert_eq!(
            fs::read(&orphan).unwrap(),
            main_bytes,
            "the orphan is a byte copy of the selected container"
        );

        let orphan_again = store.quarantine_selected(&opened.selected).unwrap();
        assert_eq!(orphan, orphan_again, "the same counter reuses the orphan");
        assert_eq!(fs::read(&orphan).unwrap(), main_bytes);
    }

    #[test]
    fn selected_candidate_cannot_be_quarantined_under_another_wallet_name() {
        let dir = tempfile::tempdir().unwrap();
        let (alice, _) = store_with_corrupt_activity(dir.path(), "alice");
        let opened = alice.unlock(PW).unwrap();
        let bob = VaultStore::new(dir.path(), "bob");

        let error = bob.quarantine_selected(&opened.selected).unwrap_err();
        assert!(error.to_string().contains("different wallet path"));
        assert!(
            atomic::try_list_orphans(&bob.main_path())
                .unwrap()
                .is_empty(),
            "a cross-wallet candidate must not create any quarantine artifact"
        );
    }

    #[test]
    fn a_promoted_crash_temp_is_removed_and_quarantine_captures_the_winner() {
        let (dir, store) = alice_store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        let mut writer = save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        let mut newer = sealed_next(
            &mut writer,
            &vault,
            b"newer-profile",
            JOURNAL,
            Some(HISTORY),
        );
        let last = newer.len() - 1;
        newer[last] ^= 0x01;
        let temp = dir.path().join("alice.ccwallet.crash.tmp");
        fs::write(&temp, &newer).unwrap();

        let opened = store.unlock(PW).unwrap();
        assert!(matches!(opened.activity, ActivitySection::Corrupt));
        assert_eq!(
            opened.selected.save_counter(),
            2,
            "the higher-counter temp won"
        );
        assert!(
            opened.selected.exact_path().ends_with("alice.ccwallet"),
            "after promotion the selection binds to main, not the consumed temp"
        );
        assert!(!temp.exists(), "the promoted crash temp is removed");
        assert_eq!(
            fs::read(store.main_path()).unwrap(),
            newer,
            "main holds the winner bytes"
        );

        let orphan = store.quarantine_selected(&opened.selected).unwrap();
        assert!(orphan.to_string_lossy().ends_with(".v1.2.orphan"));
        assert_eq!(
            fs::read(&orphan).unwrap(),
            newer,
            "the orphan copies the winner bytes via the promoted main"
        );
    }

    #[test]
    fn quarantine_fails_closed_if_the_bound_source_changed() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = store_with_corrupt_activity(dir.path(), "alice");
        let mut opened = store.unlock(PW).unwrap();
        opened
            .writer
            .save_sync(
                &Vault::create_with(PW, CHEAP).unwrap(),
                b"changed",
                JOURNAL,
                Some(HISTORY),
            )
            .unwrap();
        assert!(
            store.quarantine_selected(&opened.selected).is_err(),
            "a changed bound source must fail closed, not quarantine wrong bytes"
        );
    }

    #[test]
    fn the_mandatory_journal_round_trips_through_unlock() {
        let (_d, store) = store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        let opened = store.unlock(PW).unwrap();
        assert_eq!(&opened.journal[..], JOURNAL, "the journal round-trips");
    }

    #[test]
    fn a_container_can_omit_the_activity_section() {
        let (_d, store) = store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, None);
        let opened = store.unlock(PW).unwrap();
        assert_eq!(&opened.wallet[..], PROFILE);
        assert!(
            matches!(opened.activity, ActivitySection::Absent),
            "an omitted activity section opens as Absent, not empty history"
        );
    }

    #[test]
    fn a_single_file_holds_both_sections() {
        let (dir, store) = store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        let files: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.ends_with(".tmp"))
            .collect();
        assert_eq!(files, vec!["wallet.ccwallet".to_owned()]);
    }

    #[test]
    fn wrong_password_is_reported() {
        let (_d, store) = store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, Some(EMPTY_HISTORY));
        match store.unlock(b"nope") {
            Err(error) => assert!(error.is_wrong_password()),
            Ok(_) => panic!("expected a wrong-password error"),
        }
    }

    #[test]
    fn change_password_leaves_no_old_password_decryptable_file() {
        let (_d, store) = store();
        let old = Vault::create_with(PW, CHEAP).unwrap();
        let mut writer = save_new(&store, &old, PROFILE, JOURNAL, Some(HISTORY));
        let new = Vault::create_with(b"a new password!!", CHEAP).unwrap();
        writer
            .save_sync(&new, PROFILE, JOURNAL, Some(HISTORY))
            .unwrap();
        match store.unlock(PW) {
            Err(error) => assert!(error.is_wrong_password()),
            Ok(_) => panic!("old password still opens the wallet after re-key"),
        }
        assert_eq!(
            &store.unlock(b"a new password!!").unwrap().wallet[..],
            PROFILE
        );
    }

    #[test]
    fn read_wallet_reverts_to_the_saved_profile() {
        let (_d, store) = store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        assert_eq!(&store.read_wallet(&vault).unwrap()[..], PROFILE);
    }

    #[test]
    fn destroy_removes_the_file() {
        let (_d, store) = store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        let report = store.destroy().unwrap();
        assert!(report.residues().is_empty());
        assert_eq!(report.artifacts().len(), 1);
        let outcome = &report.artifacts()[0];
        assert_eq!(outcome.kind(), DestroyArtifactKind::Main);
        assert!(matches!(
            outcome.overwrite(),
            OverwriteOutcome::Completed { bytes } if *bytes > 0
        ));
        assert!(outcome.was_unlinked());
        assert!(outcome.directory_was_synced());
        assert!(!store.exists().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn destroy_unlinks_a_wallet_symlink_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("must-not-be-overwritten");
        fs::write(&target, b"outside-data").unwrap();
        let store = VaultStore::new(dir.path(), "alice");
        symlink(&target, store.main_path()).unwrap();

        let report = store.destroy().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"outside-data");
        assert!(!store.main_path().exists());
        assert!(matches!(
            report.artifacts()[0].overwrite(),
            OverwriteOutcome::SkippedSymlink
        ));
        assert!(report.artifacts()[0].was_unlinked());
    }

    #[cfg(unix)]
    #[test]
    fn destroy_refuses_a_hard_link_and_reports_the_exact_residue() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("shared-ciphertext");
        fs::write(&target, b"shared-data").unwrap();
        let store = VaultStore::new(dir.path(), "alice");
        fs::hard_link(&target, store.main_path()).unwrap();

        let error = store.destroy().unwrap_err();
        assert_eq!(fs::read(&target).unwrap(), b"shared-data");
        assert_eq!(
            error.report().residues(),
            &[absolute(&store.main_path())],
            "the failure identifies the exact still-linked wallet path"
        );
        assert!(
            error
                .to_string()
                .contains(&absolute(&store.main_path()).display().to_string())
        );
    }

    #[test]
    fn destroy_reports_but_retains_the_directory_level_active_lock() {
        let (dir, store) = alice_store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        let lock = match crate::paths::acquire_single_instance_lock(dir.path()).unwrap() {
            crate::paths::LockOutcome::Acquired(lock) => lock,
            crate::paths::LockOutcome::AlreadyRunning => panic!("fresh lock unexpectedly busy"),
        };
        let report = store.destroy().unwrap();
        assert_eq!(
            report.active_lock(),
            Some(absolute(&dir.path().join(crate::paths::LOCK_FILE)).as_path())
        );
        assert!(dir.path().join(crate::paths::LOCK_FILE).exists());
        drop(lock);
        assert!(!dir.path().join(crate::paths::LOCK_FILE).exists());
    }

    #[test]
    fn destroy_also_shreds_leftover_temps() {
        let (dir, store) = alice_store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        let mut writer = save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        let sealed = sealed_next(&mut writer, &vault, PROFILE, JOURNAL, Some(HISTORY));
        fs::write(dir.path().join("alice.ccwallet.leftover.tmp"), &sealed).unwrap();
        fs::write(dir.path().join("alice.ccwallet.old.orphan"), &sealed).unwrap();

        store.destroy().unwrap();

        assert!(!store.exists().unwrap());
        let residue: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            residue.is_empty(),
            "destroy leaves no wallet file, temp, or orphan behind; found {residue:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn destroy_reports_residue_it_could_not_remove() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, store) = alice_store();
        save_new(
            &store,
            &Vault::create_with(PW, CHEAP).unwrap(),
            PROFILE,
            JOURNAL,
            Some(HISTORY),
        );

        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let result = store.destroy();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

        if store.main_path().exists() {
            assert!(
                result.is_err(),
                "destroy must fail visibly when an encrypted copy survives"
            );
        }
    }

    #[test]
    fn a_crash_mid_rename_recovers_and_promotes_the_temp() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        let store = VaultStore::new(dir.path(), "alice");
        let sealed = sealed_next(
            &mut store.writer_for_new().unwrap(),
            &vault,
            PROFILE,
            JOURNAL,
            Some(HISTORY),
        );
        fs::write(dir.path().join("alice.ccwallet.crash.tmp"), &sealed).unwrap();
        assert!(store.exists().unwrap());
        assert_eq!(&store.unlock(PW).unwrap().wallet[..], PROFILE);
        assert!(
            store.main_path().exists(),
            "the recovered temp is promoted to the canonical file"
        );
    }

    #[test]
    fn a_fresh_writer_refuses_to_overwrite_a_container_that_appeared_before_the_first_save() {
        let (_dir, store) = alice_store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        let mut writer = store.writer_for_new().unwrap();
        let prepared = writer
            .prepare(&vault, PROFILE, JOURNAL, Some(HISTORY))
            .unwrap();
        let intruder = b"a pre-existing wallet container";
        fs::write(store.main_path(), intruder).unwrap();

        let error = prepared.execute().unwrap_err();
        assert!(
            matches!(&error, VaultStoreError::Io(io) if io.kind() == io::ErrorKind::AlreadyExists),
            "the fresh write refuses to clobber, got {error:?}"
        );
        assert_eq!(
            fs::read(store.main_path()).unwrap(),
            intruder,
            "the pre-existing container is left intact"
        );
    }

    #[test]
    fn a_fresh_prepare_rechecks_main_absence() {
        let (_dir, store) = alice_store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        let mut writer = store.writer_for_new().unwrap();
        fs::write(store.main_path(), b"appeared").unwrap();

        let outcome = writer.prepare(&vault, PROFILE, JOURNAL, Some(HISTORY));
        assert!(
            matches!(outcome, Err(VaultStoreError::WriterState(_))),
            "prepare rejects once a file has appeared at the fresh wallet's path"
        );
        assert_eq!(fs::read(store.main_path()).unwrap(), b"appeared");
    }

    #[test]
    fn an_overwrite_crash_recovers_the_newer_save_by_counter() {
        const NEWER: &[u8] = b"{\"seed\":\"the newer save\"}";
        let (dir, store) = alice_store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        let mut writer = save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        let newer = sealed_next(&mut writer, &vault, NEWER, JOURNAL, Some(HISTORY));
        fs::write(dir.path().join("alice.ccwallet.crash.tmp"), &newer).unwrap();

        let opened = store.unlock(PW).unwrap();
        assert_eq!(
            &opened.wallet[..],
            NEWER,
            "unlock returns the newest authenticated save, not the stale main"
        );
        assert_eq!(
            read_save_counter(&fs::read(store.main_path()).unwrap()).unwrap(),
            2,
            "the newer save is promoted to the canonical file"
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn unlock_with_survivors_derives_one_kek() {
        let (dir, store) = alice_store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        let main_bytes = fs::read(store.main_path()).unwrap();
        fs::write(dir.path().join("alice.ccwallet.crash.tmp"), &main_bytes).unwrap();
        fs::write(dir.path().join("alice.ccwallet.v1.1.orphan"), &main_bytes).unwrap();

        cc_wallet_vault::reset_kdf_invocations();
        let opened = store.unlock(PW).unwrap();
        assert_eq!(&opened.wallet[..], PROFILE);
        assert_eq!(
            cc_wallet_vault::kdf_invocations(),
            1,
            "same-generation survivors share one keyslot; the KDF runs exactly once"
        );
    }

    #[test]
    fn a_planted_foreign_temp_is_ignored_when_main_authenticates() {
        let (dir, store) = alice_store();
        let mut writer = save_new(
            &store,
            &Vault::create_with(PW, CHEAP).unwrap(),
            PROFILE,
            JOURNAL,
            Some(HISTORY),
        );
        let main_before = fs::read(store.main_path()).unwrap();
        let foreign = sealed_next(
            &mut writer,
            &Vault::create_with(b"attacker-key!!!!", CHEAP).unwrap(),
            b"evil",
            JOURNAL,
            Some(HISTORY),
        );
        let plant = dir.path().join("alice.ccwallet.evil.tmp");
        fs::write(&plant, &foreign).unwrap();

        let opened = store.unlock(PW).unwrap();
        assert_eq!(
            &opened.wallet[..],
            PROFILE,
            "main's content wins, never the foreign plant"
        );
        assert_eq!(
            fs::read(store.main_path()).unwrap(),
            main_before,
            "main preserved"
        );
        assert!(
            plant.exists(),
            "the foreign plant is left on disk, not adopted or deleted"
        );
    }

    #[test]
    fn a_clean_rekey_opens_with_the_new_password_and_rejects_the_old() {
        const PW_A: &[u8] = b"the-original-password";
        const PW_B: &[u8] = b"the-rekeyed-password!";
        let (_dir, store) = alice_store();
        let mut writer = save_new(
            &store,
            &Vault::create_with(PW_A, CHEAP).unwrap(),
            PROFILE,
            JOURNAL,
            Some(HISTORY),
        );
        writer
            .save_sync(
                &Vault::create_with(PW_B, CHEAP).unwrap(),
                PROFILE,
                JOURNAL,
                Some(HISTORY),
            )
            .unwrap();
        assert!(
            store.unlock(PW_B).is_ok(),
            "the rekeyed password opens the wallet"
        );
        match store.unlock(PW_A) {
            Err(error) => assert!(error.is_wrong_password(), "old password rejected"),
            Ok(_) => panic!("the old password must not open a rekeyed wallet"),
        }
    }

    #[test]
    fn a_pre_rekey_orphan_does_not_lock_out_a_rekeyed_main() {
        const PW_A: &[u8] = b"the-original-password";
        const PW_B: &[u8] = b"the-rekeyed-password!";
        let (dir, store) = alice_store();
        let mut writer = save_new(
            &store,
            &Vault::create_with(PW_A, CHEAP).unwrap(),
            PROFILE,
            JOURNAL,
            Some(HISTORY),
        );
        let old_a = fs::read(store.main_path()).unwrap();
        let orphan = dir.path().join("alice.ccwallet.v1.1.orphan");
        fs::write(&orphan, &old_a).unwrap();
        writer
            .save_sync(
                &Vault::create_with(PW_B, CHEAP).unwrap(),
                b"rekeyed-profile",
                JOURNAL,
                Some(HISTORY),
            )
            .unwrap();
        let main_b = fs::read(store.main_path()).unwrap();
        assert_ne!(main_b, old_a);

        assert!(
            store.unlock(PW_A).is_err(),
            "the old password is refused (no rollback to the orphan)"
        );
        let opened = store.unlock(PW_B).unwrap();
        assert_eq!(
            &opened.wallet[..],
            b"rekeyed-profile",
            "the new password opens the re-keyed main"
        );
        assert_eq!(
            fs::read(store.main_path()).unwrap(),
            main_b,
            "main must not be rolled back or overwritten"
        );
        assert!(
            orphan.exists(),
            "the old-generation orphan is preserved, never deleted"
        );
    }

    #[test]
    fn a_same_password_old_generation_orphan_is_excluded_not_adopted() {
        let (dir, store) = alice_store();
        let mut writer = save_new(
            &store,
            &Vault::create_with(PW, CHEAP).unwrap(),
            PROFILE,
            JOURNAL,
            Some(HISTORY),
        );
        let old = fs::read(store.main_path()).unwrap();
        let orphan = dir.path().join("alice.ccwallet.v1.1.orphan");
        fs::write(&orphan, &old).unwrap();
        writer
            .save_sync(
                &Vault::create_with(PW, CHEAP).unwrap(),
                b"rekeyed-profile",
                JOURNAL,
                Some(HISTORY),
            )
            .unwrap();
        let main_b = fs::read(store.main_path()).unwrap();
        assert_ne!(main_b, old);

        let opened = store.unlock(PW).unwrap();
        assert_eq!(
            &opened.wallet[..],
            b"rekeyed-profile",
            "main's newer content wins, not the same-password orphan"
        );
        assert!(
            orphan.exists(),
            "the old-generation orphan is preserved untouched"
        );
    }

    #[test]
    fn mixed_generation_survivors_with_no_main_still_fail_closed() {
        use cc_wallet_vault::Purpose;

        let (dir, store) = alice_store();
        let sections: &[(Purpose, &[u8])] =
            &[(Purpose::Wallet, PROFILE), (Purpose::Journal, JOURNAL)];
        let a = Vault::create_with(PW, CHEAP)
            .unwrap()
            .seal_container(1, sections)
            .unwrap();
        let b = Vault::create_with(b"another-key-0000", CHEAP)
            .unwrap()
            .seal_container(1, sections)
            .unwrap();
        fs::write(dir.path().join("alice.ccwallet.aa.tmp"), &a).unwrap();
        fs::write(dir.path().join("alice.ccwallet.bb.tmp"), &b).unwrap();

        assert!(
            store.unlock(PW).is_err(),
            "a generation-spanning set with no authenticated main fails closed"
        );
        assert!(dir.path().join("alice.ccwallet.aa.tmp").exists());
        assert!(dir.path().join("alice.ccwallet.bb.tmp").exists());
    }

    #[test]
    fn a_future_format_main_is_not_overwritten_by_an_older_survivor() {
        let (dir, store) = alice_store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        let mut writer = save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        let survivor = sealed_next(&mut writer, &vault, PROFILE, JOURNAL, Some(HISTORY));
        fs::write(dir.path().join("alice.ccwallet.old.tmp"), &survivor).unwrap();
        let mut future_main = fs::read(store.main_path()).unwrap();
        future_main[8..10].copy_from_slice(&9999u16.to_le_bytes());
        fs::write(store.main_path(), &future_main).unwrap();

        assert!(
            store.unlock(PW).is_err(),
            "a present future-format main that cannot authenticate must fail, not be overwritten"
        );
        assert_eq!(
            fs::read(store.main_path()).unwrap(),
            future_main,
            "the future-format main is preserved byte-for-byte"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_candidate_is_fatal_not_skipped() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, store) = alice_store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        let orphan = dir.path().join("alice.ccwallet.v1.9.orphan");
        fs::write(&orphan, fs::read(store.main_path()).unwrap()).unwrap();
        fs::set_permissions(&orphan, fs::Permissions::from_mode(0o000)).unwrap();

        let unreadable = fs::read(&orphan).is_err();
        let result = store.unlock(PW);
        fs::set_permissions(&orphan, fs::Permissions::from_mode(0o600)).unwrap();

        if unreadable {
            assert!(
                matches!(result, Err(VaultStoreError::Io(_))),
                "an unreadable candidate must fail unlock, not be skipped"
            );
        }
    }

    #[test]
    fn a_save_does_not_reset_the_counter_when_the_main_counter_is_unreadable() {
        let (_d, store) = store();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        let mut writer = save_new(&store, &vault, PROFILE, JOURNAL, Some(HISTORY));
        fs::write(store.main_path(), b"not a container").unwrap();
        assert!(
            writer
                .prepare(&vault, PROFILE, JOURNAL, Some(HISTORY))
                .is_err(),
            "the authenticated writer must reject an externally changed main"
        );
    }

    #[test]
    fn an_ambiguous_top_counter_fails_closed_without_touching_disk() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create_with(PW, CHEAP).unwrap();
        let store = VaultStore::new(dir.path(), "alice");
        let a = sealed_next(
            &mut store.writer_for_new().unwrap(),
            &vault,
            b"save-A",
            JOURNAL,
            Some(HISTORY),
        );
        let b = sealed_next(
            &mut store.writer_for_new().unwrap(),
            &vault,
            b"save-B",
            JOURNAL,
            Some(HISTORY),
        );
        fs::write(dir.path().join("alice.ccwallet.aa.tmp"), &a).unwrap();
        fs::write(dir.path().join("alice.ccwallet.bb.tmp"), &b).unwrap();

        assert!(
            store.unlock(PW).is_err(),
            "an ambiguous top counter fails closed"
        );
        assert!(!store.main_path().exists(), "no winner was promoted");
        let tmps = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(tmps, 2, "both authenticated survivors are preserved");
    }

    #[test]
    fn list_wallets_surfaces_a_wallet_recoverable_only_from_a_temp() {
        let (dir, store) = alice_store();
        let sealed = sealed_next(
            &mut store.writer_for_new().unwrap(),
            &Vault::create_with(PW, CHEAP).unwrap(),
            PROFILE,
            JOURNAL,
            Some(HISTORY),
        );
        fs::write(dir.path().join("alice.ccwallet.firstsave.tmp"), &sealed).unwrap();

        assert_eq!(
            list_wallets(dir.path()).unwrap(),
            vec!["alice"],
            "the temp-only wallet is listed"
        );
        let store = VaultStore::new(dir.path(), "alice");
        assert!(store.exists().unwrap());
        let opened = store.unlock(PW).unwrap();
        assert_eq!(&opened.wallet[..], PROFILE);
        assert!(
            store.main_path().exists(),
            "unlock promoted the temp to the canonical file"
        );
    }

    #[test]
    fn a_torn_temp_is_never_promoted_and_raises_no_phantom_wallet() {
        let (dir, store) = alice_store();
        let sealed = sealed_next(
            &mut store.writer_for_new().unwrap(),
            &Vault::create_with(PW, CHEAP).unwrap(),
            PROFILE,
            JOURNAL,
            Some(HISTORY),
        );
        let torn = &sealed[..sealed.len() - 16];
        assert!(
            torn.len() > 112,
            "the prefix is longer than a keyslot, so length+magic alone would accept it"
        );
        let torn_path = dir.path().join("alice.ccwallet.torn.tmp");
        fs::write(&torn_path, torn).unwrap();

        let store = VaultStore::new(dir.path(), "alice");

        assert!(
            !store.exists().unwrap(),
            "a body-torn container prefix is not a recoverable wallet"
        );
        assert!(
            list_wallets(dir.path()).unwrap().is_empty(),
            "and raises no phantom wallet entry"
        );
        assert!(
            store.unlock(PW).is_err(),
            "unlock over only a torn temp surfaces an error"
        );
        assert!(
            !store.main_path().exists(),
            "nothing was promoted to the canonical file"
        );
        assert!(
            torn_path.exists(),
            "the torn temp is preserved, not blindly deleted"
        );
    }
}
