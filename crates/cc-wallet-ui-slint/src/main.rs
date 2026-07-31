mod bridge;
mod build_identity;

#[cfg(target_os = "linux")]
fn harden_process() {
    use rustix::process::{DumpableBehavior, set_dumpable_behavior};

    if let Err(error) = set_dumpable_behavior(DumpableBehavior::NotDumpable) {
        eprintln!("cc-wallet: could not disable process dumping: {error}");
    }
    if let Err(error) = rlimit::setrlimit(rlimit::Resource::CORE, 0, 0) {
        eprintln!("cc-wallet: could not disable core dumps: {error}");
    }
}

#[cfg(not(target_os = "linux"))]
fn harden_process() {}

fn main() -> Result<(), slint::PlatformError> {
    match build_identity::parse_cli(std::env::args_os().skip(1)) {
        Ok(build_identity::CliMode::Version) => {
            println!("{}", build_identity::version_line());
            return Ok(());
        }
        Ok(build_identity::CliMode::Gui) => {}
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    }

    harden_process();

    let startup_cwd = match cc_wallet_app::resolve_startup_cwd() {
        Ok(startup_cwd) => startup_cwd,
        Err(error) => {
            bridge::show_startup_error(&error.to_string());
            std::process::exit(1);
        }
    };
    bridge::run(startup_cwd)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::harden_process;

    #[test]
    fn harden_process_makes_the_process_not_dumpable() {
        use rustix::process::{DumpableBehavior, dumpable_behavior};

        harden_process();
        assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
        assert_eq!(rlimit::getrlimit(rlimit::Resource::CORE).unwrap(), (0, 0));
    }
}
