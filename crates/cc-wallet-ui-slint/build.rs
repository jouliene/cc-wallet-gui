use std::path::Path;
use std::process::Command;

const UNKNOWN_SOURCE_COMMIT: &str = "unknown";

fn is_full_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn git_output(repo: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_owned())
}

fn source_commit(repo: &Path) -> String {
    if let Ok(value) = std::env::var("CC_WALLET_SOURCE_COMMIT") {
        assert!(
            is_full_commit(&value),
            "CC_WALLET_SOURCE_COMMIT must be exactly 40 lowercase hexadecimal characters"
        );
        return value;
    }

    if let Some(value) = git_output(repo, &["rev-parse", "HEAD"])
        && is_full_commit(&value)
    {
        return value;
    }

    UNKNOWN_SOURCE_COMMIT.to_owned()
}

fn main() {
    println!("cargo:rerun-if-env-changed=CC_WALLET_SOURCE_COMMIT");
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets manifest dir");
    let repo = Path::new(&manifest_dir).join("../..");
    if let Some(path) = git_output(&repo, &["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={}", repo.join(path).display());
    }
    if let Some(reference) = git_output(&repo, &["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git_output(&repo, &["rev-parse", "--git-path", &reference])
    {
        println!("cargo:rerun-if-changed={}", repo.join(path).display());
    }
    println!(
        "cargo:rustc-env=CC_WALLET_SOURCE_COMMIT={}",
        source_commit(&repo)
    );

    let config = slint_build::CompilerConfiguration::new()
        .embed_resources(slint_build::EmbedResourcesKind::EmbedFiles);
    slint_build::compile_with_config("ui/app.slint", config).expect("failed to compile Slint UI");
}
