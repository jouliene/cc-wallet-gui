use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::vault_store::read_regular_nofollow;

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaultPoint {
    TempSync,
    PostRename,
    DirectoryOpen,
    DirectorySync,
}

#[cfg(test)]
thread_local! {
    static INJECTED_FAULT: std::cell::Cell<Option<FaultPoint>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn inject_once(point: FaultPoint) {
    INJECTED_FAULT.set(Some(point));
}

#[cfg(test)]
fn fail_if_injected(point: FaultPoint) -> io::Result<()> {
    INJECTED_FAULT.with(|fault| {
        if fault.get() == Some(point) {
            fault.set(None);
            Err(io::Error::other(format!(
                "injected atomic fault at {point:?}"
            )))
        } else {
            Ok(())
        }
    })
}

#[cfg(not(test))]
fn before_temp_sync() -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
fn before_temp_sync() -> io::Result<()> {
    fail_if_injected(FaultPoint::TempSync)
}

#[cfg(not(test))]
fn after_rename() -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
fn after_rename() -> io::Result<()> {
    fail_if_injected(FaultPoint::PostRename)
}

fn sync_directory(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        #[cfg(test)]
        fail_if_injected(FaultPoint::DirectoryOpen)?;
        let dirf = fs::File::open(dir)?;
        #[cfg(test)]
        fail_if_injected(FaultPoint::DirectorySync)?;
        dirf.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

fn temp_prefix(target: &Path) -> Option<String> {
    target.file_name()?.to_str().map(|n| format!("{n}."))
}

pub(crate) fn write_atomic(target: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic_impl(target, bytes, false)
}

pub(crate) fn write_atomic_new(target: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic_impl(target, bytes, true)
}

fn write_atomic_impl(target: &Path, bytes: &[u8], noclobber: bool) -> io::Result<()> {
    let dir = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let prefix = temp_prefix(target)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target has no file name"))?;
    let mut tmp = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .tempfile_in(dir)?;
    set_owner_only(tmp.as_file())?;
    tmp.write_all(bytes)?;
    before_temp_sync()?;
    tmp.as_file().sync_all()?;

    let readback = fs::read(tmp.path())?;
    if readback != bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wallet write readback mismatch, refusing to overwrite the previous file",
        ));
    }

    if noclobber {
        tmp.persist_noclobber(target).map_err(|error| {
            if error.error.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "a wallet file already exists at this path; refusing to overwrite it",
                )
            } else {
                error.error
            }
        })?;
    } else {
        tmp.persist(target).map_err(|e| e.error)?;
    }
    after_rename()?;

    #[cfg(unix)]
    sync_directory(dir)?;
    #[cfg(windows)]
    {
        let f = fs::OpenOptions::new().write(true).open(target)?;
        f.sync_all()?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_owner_only(file: &fs::File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only(_file: &fs::File) -> io::Result<()> {
    Ok(())
}

pub(crate) fn install_orphan_copy(orphan: &Path, source_bytes: &[u8]) -> io::Result<()> {
    match read_owner_only_orphan(orphan) {
        Ok(existing) if existing == source_bytes => {
            fs::File::open(orphan)?.sync_all()?;
            let dir = orphan
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            #[cfg(unix)]
            sync_directory(dir)?;
            #[cfg(windows)]
            {
                let f = fs::OpenOptions::new().write(true).open(orphan)?;
                f.sync_all()?;
            }
            return Ok(());
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a different quarantine copy already exists at this counter",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let dir = orphan
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let prefix = temp_prefix(orphan)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "orphan has no file name"))?;
    let mut tmp = tempfile::Builder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .tempfile_in(dir)?;
    set_owner_only(tmp.as_file())?;
    tmp.write_all(source_bytes)?;
    before_temp_sync()?;
    tmp.as_file().sync_all()?;

    let readback = fs::read(tmp.path())?;
    if readback != source_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "quarantine copy readback mismatch, refusing to install",
        ));
    }

    match tmp.persist_noclobber(orphan) {
        Ok(_) => {}
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            let existing = read_owner_only_orphan(orphan)?;
            if existing != source_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "a different quarantine copy appeared at this counter",
                ));
            }
        }
        Err(error) => return Err(error.error),
    }
    after_rename()?;
    #[cfg(unix)]
    sync_directory(dir)?;
    #[cfg(windows)]
    {
        let f = fs::OpenOptions::new().write(true).open(orphan)?;
        f.sync_all()?;
    }
    Ok(())
}

fn read_owner_only_orphan(path: &Path) -> io::Result<Vec<u8>> {
    let bytes = read_regular_nofollow(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::symlink_metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "quarantine copy is not owner-only",
            ));
        }
    }
    Ok(bytes)
}

#[cfg(test)]
pub(crate) fn list_orphans(target: &Path) -> Vec<PathBuf> {
    list_residue(target, ".orphan")
}

#[cfg(test)]
pub(crate) fn list_temps(target: &Path) -> Vec<PathBuf> {
    list_residue(target, ".tmp")
}

#[cfg(test)]
fn list_residue(target: &Path, suffix: &str) -> Vec<PathBuf> {
    let Some(dir) = target.parent() else {
        return Vec::new();
    };
    let Some(prefix) = temp_prefix(target) else {
        return Vec::new();
    };
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(suffix))
        })
        .map(|e| e.path())
        .collect()
}

pub(crate) fn try_list_temps(target: &Path) -> io::Result<Vec<PathBuf>> {
    try_list_residue(target, ".tmp")
}

pub(crate) fn try_list_orphans(target: &Path) -> io::Result<Vec<PathBuf>> {
    try_list_residue(target, ".orphan")
}

fn try_list_residue(target: &Path, suffix: &str) -> io::Result<Vec<PathBuf>> {
    let Some(dir) = target.parent() else {
        return Ok(Vec::new());
    };
    let Some(prefix) = temp_prefix(target) else {
        return Ok(Vec::new());
    };
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(suffix))
        {
            out.push(entry.path());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_replaces_in_place_without_a_bak() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("wallet.ccwallet");

        write_atomic(&target, b"first").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"first");

        write_atomic(&target, b"second").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second");
        assert!(!dir.path().join("wallet.ccwallet.bak").exists());
    }

    #[test]
    fn every_atomic_durability_boundary_propagates_its_error() {
        for point in [
            FaultPoint::TempSync,
            FaultPoint::PostRename,
            FaultPoint::DirectoryOpen,
            FaultPoint::DirectorySync,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("wallet.ccwallet");
            write_atomic(&target, b"old").unwrap();
            inject_once(point);
            let error = write_atomic(&target, b"new").unwrap_err();
            assert!(error.to_string().contains("injected atomic fault"));
            match point {
                FaultPoint::TempSync => assert_eq!(fs::read(&target).unwrap(), b"old"),
                FaultPoint::PostRename | FaultPoint::DirectoryOpen | FaultPoint::DirectorySync => {
                    assert_eq!(
                        fs::read(&target).unwrap(),
                        b"new",
                        "post-rename uncertainty is surfaced, never reported as success"
                    );
                }
            }
        }
    }

    #[test]
    fn quarantine_copy_propagates_every_durability_boundary() {
        for point in [
            FaultPoint::TempSync,
            FaultPoint::PostRename,
            FaultPoint::DirectoryOpen,
            FaultPoint::DirectorySync,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let orphan = dir.path().join("wallet.ccwallet.v1.7.orphan");
            inject_once(point);
            let error = install_orphan_copy(&orphan, b"selected").unwrap_err();
            assert!(error.to_string().contains("injected atomic fault"));
            match point {
                FaultPoint::TempSync => assert!(!orphan.exists()),
                FaultPoint::PostRename | FaultPoint::DirectoryOpen | FaultPoint::DirectorySync => {
                    assert_eq!(fs::read(&orphan).unwrap(), b"selected")
                }
            }
        }
    }

    #[test]
    fn an_identical_orphan_retry_repeats_the_directory_durability_barrier() {
        let dir = tempfile::tempdir().unwrap();
        let orphan = dir.path().join("wallet.ccwallet.v1.7.orphan");

        inject_once(FaultPoint::PostRename);
        assert!(install_orphan_copy(&orphan, b"selected").is_err());
        assert_eq!(fs::read(&orphan).unwrap(), b"selected");

        inject_once(FaultPoint::DirectorySync);
        assert!(install_orphan_copy(&orphan, b"selected").is_err());
        install_orphan_copy(&orphan, b"selected").unwrap();
    }

    #[test]
    fn residue_listing_is_scoped_to_the_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let alice = dir.path().join("alice.ccwallet");
        fs::write(dir.path().join("alice.ccwallet.aa.tmp"), b"a").unwrap();
        fs::write(dir.path().join("alice.ccwallet.bb.orphan"), b"a").unwrap();
        fs::write(dir.path().join("bob.ccwallet.cc.tmp"), b"b").unwrap();
        fs::write(dir.path().join("bob.ccwallet.dd.orphan"), b"b").unwrap();

        let temps = list_temps(&alice);
        assert_eq!(temps.len(), 1, "only alice's temp is listed");
        assert!(temps[0].to_string_lossy().contains("alice.ccwallet.aa.tmp"));

        let orphans = list_orphans(&alice);
        assert_eq!(orphans.len(), 1, "only alice's orphan is listed");
        assert!(
            orphans[0]
                .to_string_lossy()
                .contains("alice.ccwallet.bb.orphan")
        );
    }

    #[test]
    fn install_orphan_copy_is_durable_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let orphan = dir.path().join("wallet.ccwallet.v1.5.orphan");

        install_orphan_copy(&orphan, b"selected-bytes").unwrap();
        assert_eq!(fs::read(&orphan).unwrap(), b"selected-bytes");
        let temps: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(temps.is_empty(), "the copy temp is renamed away, not left");

        install_orphan_copy(&orphan, b"selected-bytes").unwrap();
        assert_eq!(fs::read(&orphan).unwrap(), b"selected-bytes");
    }

    #[test]
    fn install_orphan_copy_fails_closed_on_a_divergent_collision() {
        let dir = tempfile::tempdir().unwrap();
        let orphan = dir.path().join("wallet.ccwallet.v1.5.orphan");
        install_orphan_copy(&orphan, b"original").unwrap();

        let err = install_orphan_copy(&orphan, b"different").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(&orphan).unwrap(),
            b"original",
            "the existing orphan is preserved, not clobbered"
        );
    }

    #[test]
    fn write_atomic_new_fails_closed_on_an_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("wallet.ccwallet");
        fs::write(&target, b"existing").unwrap();

        let error = write_atomic_new(&target, b"new bytes").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(&target).unwrap(),
            b"existing",
            "the pre-existing target is preserved, not clobbered"
        );
        let leftover_temp = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(
            !leftover_temp,
            "a refused noclobber write leaves no temp behind"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_installed_orphan_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let orphan = dir.path().join("wallet.ccwallet.v1.1.orphan");
        install_orphan_copy(&orphan, b"secret-copy").unwrap();
        let mode = fs::metadata(&orphan).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        fs::set_permissions(&orphan, fs::Permissions::from_mode(0o644)).unwrap();
        let error = install_orphan_copy(&orphan, b"secret-copy").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn the_written_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("wallet.ccwallet");
        write_atomic(&target, b"secret").unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
