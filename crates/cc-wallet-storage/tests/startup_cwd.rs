use std::process::Command;

use cc_wallet_storage::{LockOutcome, acquire_single_instance_lock, resolve_startup_cwd};

const CHILD_MODE: &str = "CC_WALLET_STARTUP_CWD_CHILD";
const FAULT_CHILD_MODE: &str = "CC_WALLET_STARTUP_CWD_FAULT_CHILD";

#[test]
fn child_resolves_and_probes_only_its_process_cwd() {
    if std::env::var_os(CHILD_MODE).is_none() {
        return;
    }
    let before = std::env::current_dir().expect("child current directory before startup");
    let startup = resolve_startup_cwd().expect("child resolves startup CWD");
    let root = startup.into_path();
    assert_eq!(root, before);
    let mut lock = match acquire_single_instance_lock(&root).expect("child acquires root lock") {
        LockOutcome::Acquired(lock) => lock,
        LockOutcome::AlreadyRunning => panic!("isolated child root was already locked"),
    };
    lock.probe_storage_root()
        .expect("child completes full startup probe");
    assert_eq!(
        std::env::current_dir().expect("child current directory after startup"),
        before,
        "startup must never chdir"
    );
    lock.release().expect("child releases root lock");
    println!("startup-root={}", root.display());
}

#[cfg(unix)]
#[test]
fn child_faulted_probe_stays_in_its_process_cwd() {
    use std::os::unix::fs::PermissionsExt;

    if std::env::var_os(FAULT_CHILD_MODE).is_none() {
        return;
    }
    let before = std::env::current_dir().expect("fault child current directory before startup");
    let startup = resolve_startup_cwd().expect("fault child resolves startup CWD");
    let root = startup.into_path();
    assert_eq!(root, before);
    let mut lock =
        match acquire_single_instance_lock(&root).expect("fault child acquires root lock") {
            LockOutcome::Acquired(lock) => lock,
            LockOutcome::AlreadyRunning => panic!("isolated fault child root was already locked"),
        };

    let original = std::fs::metadata(&root)
        .expect("fault child reads root permissions")
        .permissions();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500))
        .expect("fault child makes its root non-writable");
    let probe = lock.probe_storage_root();
    std::fs::set_permissions(&root, original).expect("fault child restores root permissions");

    let error = probe.expect_err("owner-unwritable root must fail its create-new probe");
    assert!(error.to_string().contains(&root.display().to_string()));
    assert!(error.to_string().contains("probe"));
    assert_eq!(
        std::env::current_dir().expect("fault child current directory after startup"),
        before,
        "faulted startup must never chdir"
    );
    lock.release().expect("fault child releases root lock");
    println!("fault-startup-root={}", root.display());
}

#[test]
fn a_process_cwd_is_the_only_root_and_environment_cannot_redirect_it() {
    let root = tempfile::tempdir().unwrap();
    let redirect = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let executable = std::env::current_exe().unwrap();

    let output = Command::new(executable)
        .arg("--exact")
        .arg("child_resolves_and_probes_only_its_process_cwd")
        .arg("--nocapture")
        .current_dir(root.path())
        .env(CHILD_MODE, "1")
        .env("CC_WALLET_DATA_DIR", redirect.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("XDG_DATA_HOME", xdg.path())
        .env("XDG_CACHE_HOME", xdg.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains(&format!("startup-root={}", root.path().display()))
    );
    for untouched in [redirect.path(), home.path(), xdg.path()] {
        assert!(
            std::fs::read_dir(untouched).unwrap().next().is_none(),
            "startup wrote outside CWD at {}",
            untouched.display()
        );
    }
    assert!(
        std::fs::read_dir(root.path()).unwrap().next().is_none(),
        "the clean lock/probe lifecycle must leave no residue"
    );
}

#[cfg(unix)]
#[test]
fn a_faulted_process_probe_cannot_redirect_or_leave_residue() {
    let root = tempfile::tempdir().unwrap();
    let redirect = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let executable = std::env::current_exe().unwrap();

    let output = Command::new(executable)
        .arg("--exact")
        .arg("child_faulted_probe_stays_in_its_process_cwd")
        .arg("--nocapture")
        .current_dir(root.path())
        .env(FAULT_CHILD_MODE, "1")
        .env("CC_WALLET_DATA_DIR", redirect.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("XDG_DATA_HOME", xdg.path())
        .env("XDG_CACHE_HOME", xdg.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fault child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains(&format!("fault-startup-root={}", root.path().display()))
    );
    for untouched in [redirect.path(), home.path(), xdg.path()] {
        assert!(
            std::fs::read_dir(untouched).unwrap().next().is_none(),
            "faulted startup wrote outside CWD at {}",
            untouched.display()
        );
    }
    assert!(
        std::fs::read_dir(root.path()).unwrap().next().is_none(),
        "the faulted lock/probe lifecycle must leave no residue"
    );
}
