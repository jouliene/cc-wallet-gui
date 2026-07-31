use std::path::{Path, PathBuf};

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut sources = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).expect("Tycho source directory is readable") {
            let path = entry.expect("Tycho source entry is readable").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                sources.push(path);
            }
        }
    }
    sources.sort();
    sources
}

#[test]
fn t_no_unix_only_in_tycho_crate() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = rust_sources(&source_root);
    assert!(
        !sources.is_empty(),
        "Tycho source inventory must not be empty"
    );

    for path in sources {
        let source = std::fs::read_to_string(&path).expect("Tycho source is UTF-8");
        let lowered = source.to_lowercase();
        let compact: String = lowered
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        for (start, _) in compact.match_indices("#[cfg(") {
            let directive = &compact[start..];
            let end = directive
                .find(']')
                .expect("a parsed Rust source has a complete cfg attribute");
            assert!(
                !directive[..=end].contains("unix"),
                "Unix-only cfg escaped into {}",
                path.display()
            );
        }
        assert!(
            !lowered.contains("unixstream"),
            "UnixStream escaped into {}",
            path.display()
        );
        assert!(
            !lowered.contains("tarpc"),
            "tarpc escaped into {}",
            path.display()
        );
    }
}
