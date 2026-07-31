use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

use crate::error::{StorageError, StorageResult};

pub const LOCK_FILE: &str = ".ccwallet.lock";
const PROBE_PREFIX: &str = ".ccwallet-storage-probe-";
const PROBE_BYTES: usize = 64;

#[derive(Debug)]
pub struct StartupCwd(PathBuf);

impl StartupCwd {
    pub fn into_path(self) -> PathBuf {
        self.0
    }
}

pub fn resolve_startup_cwd() -> StorageResult<StartupCwd> {
    let dir = std::env::current_dir().map_err(StorageError::CurrentDirectory)?;
    validate_startup_cwd(dir)
}

fn validate_startup_cwd(dir: PathBuf) -> StorageResult<StartupCwd> {
    if !dir.is_absolute() {
        return Err(StorageError::invalid_startup_root(
            dir,
            "the operating system returned a non-absolute current directory",
        ));
    }
    let Some(visible) = dir.to_str() else {
        return Err(StorageError::invalid_startup_root(
            dir,
            "the path contains non-UTF-8 bytes and cannot be shown exactly in the wallet UI",
        ));
    };
    if visible.chars().any(char::is_control) {
        return Err(StorageError::invalid_startup_root(
            dir,
            "the path contains control characters and cannot be shown safely in the wallet UI",
        ));
    }
    let metadata = std::fs::symlink_metadata(&dir).map_err(|error| {
        StorageError::invalid_startup_root(
            dir.clone(),
            format!("could not inspect the existing directory: {error}"),
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(StorageError::invalid_startup_root(
            dir,
            "the path is not an existing real directory",
        ));
    }
    Ok(StartupCwd(dir))
}

fn random_probe_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|error| {
        io::Error::other(format!("operating-system randomness failed: {error}"))
    })?;
    Ok(bytes)
}

fn probe_token() -> io::Result<String> {
    use std::fmt::Write as _;

    let bytes = random_probe_bytes::<16>()?;
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut token, "{byte:02x}").expect("writing to a String is infallible");
    }
    Ok(token)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupProbeFault {
    Create,
    Write,
    FileSync,
    Readback,
    ReadbackMismatch,
    Rename,
    DirectoryOpen,
    DirectorySyncAfterRename,
    Unlink,
    DirectorySyncAfterUnlink,
}

#[cfg(test)]
thread_local! {
    static STARTUP_PROBE_FAULT: std::cell::Cell<Option<StartupProbeFault>> = const {
        std::cell::Cell::new(None)
    };
    static STARTUP_PROBE_CLEANUP_SYNCS: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
fn inject_startup_probe_fault(point: StartupProbeFault) {
    STARTUP_PROBE_FAULT.set(Some(point));
}

#[cfg(test)]
fn fail_startup_probe_at(point: StartupProbeFault) -> io::Result<()> {
    STARTUP_PROBE_FAULT.with(|fault| {
        if fault.get() == Some(point) {
            fault.set(None);
            Err(io::Error::other(format!(
                "injected startup storage probe fault at {point:?}"
            )))
        } else {
            Ok(())
        }
    })
}

#[cfg(not(test))]
fn fail_startup_probe_at(_point: StartupProbeFault) -> io::Result<()> {
    Ok(())
}

pub struct InstanceLock {
    file: Option<File>,
    path: PathBuf,
    dir: PathBuf,
    owner_record: Vec<u8>,
}

pub enum LockOutcome {
    Acquired(InstanceLock),
    AlreadyRunning,
}

struct ProbeCleanup {
    dir: PathBuf,
    first: PathBuf,
    second: PathBuf,
    file: Option<File>,
    armed: bool,
}

impl ProbeCleanup {
    fn new(dir: &Path, first: PathBuf, second: PathBuf) -> Self {
        Self {
            dir: dir.to_path_buf(),
            first,
            second,
            file: None,
            armed: true,
        }
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if !self.armed {
            return Ok(());
        }
        let mut problems = Vec::new();
        for path in [&self.first, &self.second] {
            match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    problems.push(format!("could not inspect {}: {error}", path.display()))
                }
                Ok(_) => {
                    let owned = self
                        .file
                        .as_ref()
                        .is_some_and(|file| safe_lock_identity(path, file));
                    if !owned {
                        problems.push(format!(
                            "refused to remove probe pathname whose inode changed: {}",
                            path.display()
                        ));
                        continue;
                    }
                    match std::fs::remove_file(path) {
                        Ok(()) => {}
                        Err(error) => {
                            problems.push(format!("could not remove {}: {error}", path.display()))
                        }
                    }
                }
            }
        }
        #[cfg(test)]
        STARTUP_PROBE_CLEANUP_SYNCS.set(STARTUP_PROBE_CLEANUP_SYNCS.get() + 1);
        if let Err(error) = sync_directory(&self.dir) {
            problems.push(format!(
                "could not persist probe cleanup in {}: {error}",
                self.dir.display()
            ));
        }
        self.file.take();
        self.armed = false;
        if problems.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(problems.join("; ")))
        }
    }

    fn finish(&mut self) {
        self.file.take();
        self.armed = false;
    }
}

impl Drop for ProbeCleanup {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("CC Wallet startup-probe cleanup failed: {error}");
        }
    }
}

fn io_at(operation: &str, path: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{operation} {} failed: {error}", path.display()),
    )
}

#[cfg(target_os = "linux")]
fn process_start_token() -> io::Result<String> {
    let stat = std::fs::read_to_string("/proc/self/stat")?;
    let close = stat
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed /proc/self/stat"))?;
    stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .map(str::to_owned)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing process start token"))
}

#[cfg(not(target_os = "linux"))]
fn process_start_token() -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "process start tokens are implemented only for the Linux release target",
    ))
}

fn owner_record() -> io::Result<Vec<u8>> {
    Ok(format!(
        "pid={}\nstart_ticks={}\n",
        std::process::id(),
        process_start_token()?
    )
    .into_bytes())
}

#[cfg(unix)]
fn set_lock_owner_only(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_lock_owner_only(_file: &File) -> io::Result<()> {
    Ok(())
}

fn sync_directory(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

#[cfg(unix)]
fn same_file(path: &Path, file: &File) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(path_meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    let Ok(file_meta) = file.metadata() else {
        return false;
    };
    path_meta.dev() == file_meta.dev() && path_meta.ino() == file_meta.ino()
}

#[cfg(unix)]
fn safe_lock_identity(path: &Path, file: &File) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(path_meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    let Ok(file_meta) = file.metadata() else {
        return false;
    };
    path_meta.is_file()
        && !path_meta.file_type().is_symlink()
        && path_meta.nlink() == 1
        && file_meta.is_file()
        && file_meta.nlink() == 1
        && path_meta.dev() == file_meta.dev()
        && path_meta.ino() == file_meta.ino()
}

#[cfg(not(unix))]
fn safe_lock_identity(path: &Path, file: &File) -> bool {
    same_file(path, file)
}

#[cfg(not(unix))]
fn same_file(path: &Path, _file: &File) -> bool {
    path.is_file()
}

impl InstanceLock {
    pub fn root(&self) -> &Path {
        &self.dir
    }

    pub fn probe_storage_root(&self) -> io::Result<()> {
        let lock_file = self.file.as_ref().ok_or_else(|| {
            io_at(
                "running startup storage probe without a held lock at",
                &self.dir,
                io::Error::other("the instance lock was already released"),
            )
        })?;
        if !safe_lock_identity(&self.path, lock_file) {
            return Err(io_at(
                "validating the held lock before startup storage probe at",
                &self.path,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "lock pathname or inode changed before the probe",
                ),
            ));
        }

        let first_token = probe_token()
            .map_err(|error| io_at("creating an unpredictable probe name in", &self.dir, error))?;
        let second_token = probe_token().map_err(|error| {
            io_at(
                "creating an unpredictable rename target in",
                &self.dir,
                error,
            )
        })?;
        if first_token == second_token {
            return Err(io_at(
                "creating independent startup probe names in",
                &self.dir,
                io::Error::other("operating-system randomness repeated a probe token"),
            ));
        }
        let first = self
            .dir
            .join(format!("{PROBE_PREFIX}{first_token}.written"));
        let second = self
            .dir
            .join(format!("{PROBE_PREFIX}{second_token}.renamed"));
        let payload = random_probe_bytes::<PROBE_BYTES>()
            .map_err(|error| io_at("creating random probe bytes in", &self.dir, error))?;
        let mut cleanup = ProbeCleanup::new(&self.dir, first.clone(), second.clone());

        let result = (|| -> io::Result<()> {
            fail_startup_probe_at(StartupProbeFault::Create)
                .map_err(|error| io_at("creating startup probe in", &self.dir, error))?;
            let mut options = OpenOptions::new();
            options.create_new(true).read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
                options.custom_flags(libc::O_NOFOLLOW);
            }
            let file = options
                .open(&first)
                .map_err(|error| io_at("creating owner-only startup probe at", &first, error))?;
            cleanup.file = Some(file);
            let file = cleanup
                .file
                .as_mut()
                .expect("probe file was just installed");
            set_lock_owner_only(file)
                .map_err(|error| io_at("setting startup probe owner-only at", &first, error))?;
            if !safe_lock_identity(&first, file) {
                return Err(io_at(
                    "validating owner-only startup probe at",
                    &first,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "probe is not the exact singly-linked regular file opened",
                    ),
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if file.metadata()?.permissions().mode() & 0o077 != 0 {
                    return Err(io_at(
                        "validating startup probe permissions at",
                        &first,
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "probe permissions are not owner-only",
                        ),
                    ));
                }
            }

            fail_startup_probe_at(StartupProbeFault::Write)
                .map_err(|error| io_at("writing startup probe at", &first, error))?;
            file.write_all(&payload)
                .map_err(|error| io_at("writing startup probe at", &first, error))?;
            fail_startup_probe_at(StartupProbeFault::FileSync)
                .map_err(|error| io_at("syncing startup probe at", &first, error))?;
            file.sync_all()
                .map_err(|error| io_at("syncing startup probe at", &first, error))?;

            fail_startup_probe_at(StartupProbeFault::Readback)
                .map_err(|error| io_at("reading back startup probe at", &first, error))?;
            let mut readback = crate::vault_store::read_regular_nofollow(&first)
                .map_err(|error| io_at("reading back startup probe at", &first, error))?;
            if fail_startup_probe_at(StartupProbeFault::ReadbackMismatch).is_err()
                && let Some(byte) = readback.first_mut()
            {
                *byte ^= 0xff;
            }
            if readback != payload {
                return Err(io_at(
                    "comparing startup probe readback at",
                    &first,
                    io::Error::new(io::ErrorKind::InvalidData, "probe readback mismatch"),
                ));
            }

            match std::fs::symlink_metadata(&second) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(io_at(
                        "checking startup probe rename target at",
                        &second,
                        error,
                    ));
                }
                Ok(_) => {
                    return Err(io_at(
                        "checking startup probe rename target at",
                        &second,
                        io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "unpredictable probe target already exists",
                        ),
                    ));
                }
            }
            fail_startup_probe_at(StartupProbeFault::Rename)
                .map_err(|error| io_at("renaming startup probe to", &second, error))?;
            std::fs::rename(&first, &second)
                .map_err(|error| io_at("renaming startup probe to", &second, error))?;
            if !safe_lock_identity(
                &second,
                cleanup.file.as_ref().expect("probe file remains open"),
            ) {
                return Err(io_at(
                    "validating renamed startup probe at",
                    &second,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "renamed probe pathname does not identify the opened file",
                    ),
                ));
            }

            fail_startup_probe_at(StartupProbeFault::DirectoryOpen)
                .map_err(|error| io_at("opening launch folder", &self.dir, error))?;
            let directory = File::open(&self.dir)
                .map_err(|error| io_at("opening launch folder", &self.dir, error))?;
            fail_startup_probe_at(StartupProbeFault::DirectorySyncAfterRename)
                .map_err(|error| io_at("syncing renamed startup probe in", &self.dir, error))?;
            directory
                .sync_all()
                .map_err(|error| io_at("syncing renamed startup probe in", &self.dir, error))?;

            fail_startup_probe_at(StartupProbeFault::Unlink)
                .map_err(|error| io_at("unlinking startup probe at", &second, error))?;
            std::fs::remove_file(&second)
                .map_err(|error| io_at("unlinking startup probe at", &second, error))?;
            fail_startup_probe_at(StartupProbeFault::DirectorySyncAfterUnlink)
                .map_err(|error| io_at("syncing startup probe removal in", &self.dir, error))?;
            directory
                .sync_all()
                .map_err(|error| io_at("syncing startup probe removal in", &self.dir, error))?;

            for path in [&first, &second] {
                match std::fs::symlink_metadata(path) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(io_at("verifying startup probe cleanup at", path, error));
                    }
                    Ok(_) => {
                        return Err(io_at(
                            "verifying startup probe cleanup at",
                            path,
                            io::Error::other("probe residue remains after successful unlink"),
                        ));
                    }
                }
            }
            if !safe_lock_identity(&self.path, lock_file) {
                return Err(io_at(
                    "revalidating the held lock after startup storage probe at",
                    &self.path,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "lock pathname or inode changed during the probe",
                    ),
                ));
            }
            cleanup.finish();
            Ok(())
        })();

        if let Err(error) = result {
            let cleanup_result = cleanup.cleanup();
            return match cleanup_result {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(io::Error::new(
                    error.kind(),
                    format!(
                        "{error}; startup probe cleanup in {} also failed: {cleanup_error}",
                        self.dir.display()
                    ),
                )),
            };
        }
        Ok(())
    }

    pub fn release(&mut self) -> io::Result<()> {
        self.release_inner()
    }

    fn release_inner(&mut self) -> io::Result<()> {
        let Some(file) = self.file.as_mut() else {
            return Ok(());
        };
        file.rewind()
            .map_err(|error| io_at("seeking lock owner record at", &self.path, error))?;
        let mut held_record = Vec::new();
        file.read_to_end(&mut held_record)
            .map_err(|error| io_at("reading lock owner record at", &self.path, error))?;
        let path_matches = same_file(&self.path, file)
            && std::fs::read(&self.path).is_ok_and(|bytes| bytes == self.owner_record)
            && held_record == self.owner_record;
        if !path_matches {
            return Err(io_at(
                "validating owned instance lock before release at",
                &self.path,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "lock pathname, inode, or owner token changed",
                ),
            ));
        }
        let directory = File::open(&self.dir)
            .map_err(|error| io_at("opening lock directory", &self.dir, error))?;
        directory
            .sync_all()
            .map_err(|error| io_at("preflighting lock-directory sync", &self.dir, error))?;
        std::fs::remove_file(&self.path)
            .map_err(|error| io_at("unlinking owned instance lock at", &self.path, error))?;
        let post_unlink_sync_error = directory.sync_all().err();

        drop(self.file.take());
        if let Some(error) = post_unlink_sync_error {
            eprintln!(
                "CC Wallet lock was released, but persisting removal of {} failed: {error}",
                self.path.display()
            );
        }
        Ok(())
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        if let Err(error) = self.release_inner() {
            eprintln!("CC Wallet lock cleanup failed: {error}");
        }
    }
}

pub fn acquire_single_instance_lock(dir: &Path) -> io::Result<LockOutcome> {
    let dir = std::fs::canonicalize(dir)
        .map_err(|error| io_at("resolving instance-lock directory", dir, error))?;
    let path = dir.join(LOCK_FILE);
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&path)
        .map_err(|error| io_at("opening instance lock at", &path, error))?;
    match file.try_lock() {
        Ok(()) => {
            if !safe_lock_identity(&path, &file) {
                return Err(io_at(
                    "validating mandatory instance lock at",
                    &path,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "lock path is not the exact singly-linked regular file opened",
                    ),
                ));
            }
            set_lock_owner_only(&file)
                .map_err(|error| io_at("setting owner-only lock permissions at", &path, error))?;
            let owner_record = owner_record()
                .map_err(|error| io_at("creating lock owner record for", &path, error))?;
            file.set_len(0)
                .map_err(|error| io_at("truncating stale lock owner record at", &path, error))?;
            file.rewind()
                .map_err(|error| io_at("seeking lock owner record at", &path, error))?;
            file.write_all(&owner_record)
                .map_err(|error| io_at("writing lock owner record at", &path, error))?;
            file.sync_all()
                .map_err(|error| io_at("syncing lock owner record at", &path, error))?;
            if !safe_lock_identity(&path, &file) {
                return Err(io_at(
                    "revalidating mandatory instance lock at",
                    &path,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "lock path changed while its owner record was written",
                    ),
                ));
            }
            sync_directory(&dir).map_err(|error| io_at("syncing lock directory", &dir, error))?;
            Ok(LockOutcome::Acquired(InstanceLock {
                file: Some(file),
                path,
                dir,
                owner_record,
            }))
        }
        Err(std::fs::TryLockError::WouldBlock) => Ok(LockOutcome::AlreadyRunning),
        Err(std::fs::TryLockError::Error(error)) => {
            Err(io_at("acquiring mandatory instance lock at", &path, error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_cwd_is_absolute_and_opaque() {
        let resolved = resolve_startup_cwd().unwrap().into_path();
        assert!(resolved.is_absolute());
        assert!(resolved.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_startup_root_is_preserved_without_path_disclosure() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let parent = tempfile::tempdir().unwrap();
        let leaf = OsString::from_vec(vec![b'w', b'a', b'l', b'l', b'e', b't', 0xff]);
        let root = parent.path().join(leaf);
        std::fs::create_dir(&root).unwrap();
        let error = validate_startup_cwd(root.clone()).unwrap_err();
        match &error {
            StorageError::InvalidStartupRoot { path, reason } => {
                assert_eq!(path, &root);
                assert!(reason.contains("non-UTF-8"));
            }
            StorageError::CurrentDirectory(_) => panic!("validation returned the wrong error"),
        }
        let display = error.to_string();
        assert!(display.contains("non-UTF-8"));
        assert!(!display.contains("\\xFF") && !display.contains("\\xff"));
        assert!(!display.contains(char::REPLACEMENT_CHARACTER));
    }

    #[test]
    fn control_character_startup_root_is_refused_before_normal_operation() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("wallet\nroot");
        std::fs::create_dir(&root).unwrap();
        let error = validate_startup_cwd(root).unwrap_err().to_string();
        assert!(error.contains("control characters"));
    }

    #[test]
    fn single_instance_lock_excludes_a_second_holder() {
        let dir = tempfile::tempdir().unwrap();
        let first = acquire_single_instance_lock(dir.path()).unwrap();
        assert!(matches!(first, LockOutcome::Acquired(_)));
        match acquire_single_instance_lock(dir.path()).unwrap() {
            LockOutcome::AlreadyRunning => {}
            LockOutcome::Acquired(_) => panic!("second lock must not be granted"),
        }
        drop(first);
        assert!(matches!(
            acquire_single_instance_lock(dir.path()).unwrap(),
            LockOutcome::Acquired(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn lock_record_is_owner_only_and_unlinked_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let lock = match acquire_single_instance_lock(dir.path()).unwrap() {
            LockOutcome::Acquired(lock) => lock,
            LockOutcome::AlreadyRunning => panic!("fresh directory unexpectedly locked"),
        };
        let path = dir.path().join(LOCK_FILE);
        let record = std::fs::read_to_string(&path).unwrap();
        assert!(record.contains(&format!("pid={}", std::process::id())));
        assert!(record.contains("start_ticks="));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(lock);
        assert!(!path.exists(), "clean owner exit removes the lock sidecar");
    }

    #[test]
    fn full_startup_probe_runs_under_the_lock_and_leaves_no_residue() {
        let dir = tempfile::tempdir().unwrap();
        let mut lock = match acquire_single_instance_lock(dir.path()).unwrap() {
            LockOutcome::Acquired(lock) => lock,
            LockOutcome::AlreadyRunning => panic!("fresh directory unexpectedly locked"),
        };
        assert_eq!(lock.root(), std::fs::canonicalize(dir.path()).unwrap());
        lock.probe_storage_root().unwrap();
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(LOCK_FILE)]);
        lock.release().unwrap();
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[test]
    fn every_startup_probe_boundary_fails_visible_and_cleans_residue() {
        for point in [
            StartupProbeFault::Create,
            StartupProbeFault::Write,
            StartupProbeFault::FileSync,
            StartupProbeFault::Readback,
            StartupProbeFault::ReadbackMismatch,
            StartupProbeFault::Rename,
            StartupProbeFault::DirectoryOpen,
            StartupProbeFault::DirectorySyncAfterRename,
            StartupProbeFault::Unlink,
            StartupProbeFault::DirectorySyncAfterUnlink,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut lock = match acquire_single_instance_lock(dir.path()).unwrap() {
                LockOutcome::Acquired(lock) => lock,
                LockOutcome::AlreadyRunning => panic!("fresh directory unexpectedly locked"),
            };
            inject_startup_probe_fault(point);
            let error = lock.probe_storage_root().unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&dir.path().display().to_string())
            );
            assert!(
                error.to_string().contains("probe"),
                "fault {point:?} returned an unqualified error: {error}"
            );
            let names: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            assert_eq!(
                names,
                vec![std::ffi::OsString::from(LOCK_FILE)],
                "fault {point:?} left probe residue"
            );
            lock.release().unwrap();
        }
    }

    #[test]
    fn cleanup_retries_directory_sync_after_a_post_unlink_sync_failure() {
        let dir = tempfile::tempdir().unwrap();
        let mut lock = match acquire_single_instance_lock(dir.path()).unwrap() {
            LockOutcome::Acquired(lock) => lock,
            LockOutcome::AlreadyRunning => panic!("fresh directory unexpectedly locked"),
        };
        STARTUP_PROBE_CLEANUP_SYNCS.set(0);
        inject_startup_probe_fault(StartupProbeFault::DirectorySyncAfterUnlink);
        let error = lock.probe_storage_root().unwrap_err();
        assert!(error.to_string().contains("syncing startup probe removal"));
        assert_eq!(
            STARTUP_PROBE_CLEANUP_SYNCS.get(),
            1,
            "cleanup must retry directory fsync even after unlink removed both names"
        );
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "only the held lock may remain"
        );
        lock.release().unwrap();
    }

    #[test]
    fn probe_cleanup_never_unlinks_a_replacement_inode() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("probe.written");
        let second = dir.path().join("probe.renamed");
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&first)
            .unwrap();
        let mut cleanup = ProbeCleanup::new(dir.path(), first.clone(), second);
        cleanup.file = Some(file);

        std::fs::remove_file(&first).unwrap();
        std::fs::write(&first, b"unrelated replacement").unwrap();
        let error = cleanup.cleanup().unwrap_err();
        assert!(error.to_string().contains("inode changed"));
        assert_eq!(std::fs::read(&first).unwrap(), b"unrelated replacement");
    }

    #[test]
    fn a_released_lock_cannot_authorize_a_later_probe() {
        let dir = tempfile::tempdir().unwrap();
        let mut lock = match acquire_single_instance_lock(dir.path()).unwrap() {
            LockOutcome::Acquired(lock) => lock,
            LockOutcome::AlreadyRunning => panic!("fresh directory unexpectedly locked"),
        };
        lock.release().unwrap();
        let error = lock.probe_storage_root().unwrap_err();
        assert!(error.to_string().contains("already released"));
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[test]
    fn a_missing_root_is_not_created_and_the_absolute_path_is_visible() {
        let parent = tempfile::tempdir().unwrap();
        let missing = parent.path().join("missing-wallet-root");
        let error = match acquire_single_instance_lock(&missing) {
            Ok(_) => panic!("missing root unexpectedly acquired a lock"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(&missing.display().to_string()));
        assert!(!missing.exists());
    }

    #[cfg(unix)]
    #[test]
    fn an_unwritable_locked_root_fails_the_probe_with_its_absolute_path() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let mut lock = match acquire_single_instance_lock(dir.path()).unwrap() {
            LockOutcome::Acquired(lock) => lock,
            LockOutcome::AlreadyRunning => panic!("fresh directory unexpectedly locked"),
        };
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = lock.probe_storage_root();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = result.expect_err("owner-unwritable root must fail the create-new probe");
        assert!(
            error
                .to_string()
                .contains(&dir.path().display().to_string())
        );
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(LOCK_FILE)]);
        lock.release().unwrap();
    }

    #[test]
    fn stale_owner_record_is_replaced_only_after_the_os_lock_is_acquired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LOCK_FILE);
        std::fs::write(&path, b"pid=999999\nstart_ticks=1\n").unwrap();
        let lock = match acquire_single_instance_lock(dir.path()).unwrap() {
            LockOutcome::Acquired(lock) => lock,
            LockOutcome::AlreadyRunning => panic!("stale unlocked record blocked startup"),
        };
        let record = std::fs::read_to_string(&path).unwrap();
        assert!(record.contains(&format!("pid={}", std::process::id())));
        drop(lock);
        assert!(!path.exists());
    }

    #[test]
    fn explicit_release_refuses_a_changed_owner_token_and_keeps_the_os_lock() {
        let dir = tempfile::tempdir().unwrap();
        let mut lock = match acquire_single_instance_lock(dir.path()).unwrap() {
            LockOutcome::Acquired(lock) => lock,
            LockOutcome::AlreadyRunning => panic!("fresh directory unexpectedly locked"),
        };
        let path = dir.path().join(LOCK_FILE);
        let owner = lock.owner_record.clone();
        std::fs::write(&path, b"pid=1\nstart_ticks=1\n").unwrap();

        let error = lock.release().unwrap_err();
        assert!(error.to_string().contains(&path.display().to_string()));
        assert!(matches!(
            acquire_single_instance_lock(dir.path()).unwrap(),
            LockOutcome::AlreadyRunning
        ));

        std::fs::write(&path, owner).unwrap();
        lock.release().unwrap();
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn lock_acquisition_refuses_symlink_and_hardlink_targets_without_mutating_them() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        for hard in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            let target = outside.path().join("unrelated");
            std::fs::write(&target, b"do not touch").unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
            let lock_path = dir.path().join(LOCK_FILE);
            if hard {
                std::fs::hard_link(&target, &lock_path).unwrap();
            } else {
                symlink(&target, &lock_path).unwrap();
            }

            let error = match acquire_single_instance_lock(dir.path()) {
                Ok(_) => panic!("a planted link must not become the process lock"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(&lock_path.display().to_string()));
            assert_eq!(std::fs::read(&target).unwrap(), b"do not touch");
            assert_eq!(
                std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o640
            );
        }
    }
}
