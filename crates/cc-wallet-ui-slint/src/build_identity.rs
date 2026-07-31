use std::ffi::OsString;

pub(crate) const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) const SOURCE_COMMIT: &str = env!("CC_WALLET_SOURCE_COMMIT");

pub(crate) const UNKNOWN_SOURCE_COMMIT: &str = "unknown";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CliMode {
    Gui,
    Version,
}

pub(crate) fn parse_cli(args: impl IntoIterator<Item = OsString>) -> Result<CliMode, String> {
    let args: Vec<OsString> = args.into_iter().collect();
    match args.as_slice() {
        [] => Ok(CliMode::Gui),
        [argument] if argument == "--version" => Ok(CliMode::Version),
        _ => Err("usage: cc-wallet-gui [--version]".to_owned()),
    }
}

pub(crate) fn is_full_source_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn version_line() -> String {
    assert!(SOURCE_COMMIT == UNKNOWN_SOURCE_COMMIT || is_full_source_commit(SOURCE_COMMIT));
    format!("cc-wallet-gui {APP_VERSION} ({SOURCE_COMMIT})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_output_binds_package_version_and_build_source() {
        assert_eq!(
            version_line(),
            format!("cc-wallet-gui {APP_VERSION} ({SOURCE_COMMIT})")
        );
        assert!(SOURCE_COMMIT == UNKNOWN_SOURCE_COMMIT || is_full_source_commit(SOURCE_COMMIT));
    }

    #[test]
    fn command_line_has_only_gui_and_exact_version_modes() {
        assert_eq!(parse_cli([]), Ok(CliMode::Gui));
        assert_eq!(
            parse_cli([OsString::from("--version")]),
            Ok(CliMode::Version)
        );
        assert!(parse_cli([OsString::from("--help")]).is_err());
        assert!(parse_cli([OsString::from("--version"), OsString::from("extra")]).is_err());
    }
}
