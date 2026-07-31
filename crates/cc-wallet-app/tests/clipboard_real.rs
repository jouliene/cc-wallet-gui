use std::process::Command;
use std::sync::Mutex;

use cc_wallet_app::clipboard::{ClipboardBackend, Selection, SystemClipboard};

static CLIPBOARD_TEST_LOCK: Mutex<()> = Mutex::new(());

fn clipboard_guard() -> std::sync::MutexGuard<'static, ()> {
    CLIPBOARD_TEST_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

const PHRASE: &str =
    "abandon ability able about above absent absorb abstract absurd abuse access accident";
const PROBE: &str = "cc-wallet-clipboard-probe-4a1f7e9c";

fn tool_exists(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .is_ok_and(|out| out.status.success())
}

enum Reader {
    Xclip,
    WlPaste,
}

impl Reader {
    fn binary(&self) -> &'static str {
        match self {
            Reader::Xclip => "xclip",
            Reader::WlPaste => "wl-paste",
        }
    }

    fn read(&self, selection: Selection) -> String {
        let primary = matches!(selection, Selection::Primary);
        let out = match self {
            Reader::Xclip => {
                let sel = if primary { "primary" } else { "clipboard" };
                Command::new("xclip")
                    .args(["-o", "-selection", sel])
                    .output()
                    .expect("xclip should run")
            }
            Reader::WlPaste => {
                let mut cmd = Command::new("wl-paste");
                cmd.arg("--no-newline");
                if primary {
                    cmd.arg("--primary");
                }
                cmd.output().expect("wl-paste should run")
            }
        };
        if out.status.success() {
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        } else {
            String::new()
        }
    }
}

struct RestoreClipboard {
    saved_clipboard: String,
    saved_primary: String,
}

impl Drop for RestoreClipboard {
    fn drop(&mut self) {
        let mut clipboard = SystemClipboard;
        let _ = clipboard.set(Selection::Clipboard, &self.saved_clipboard);
        let _ = clipboard.set(Selection::Primary, &self.saved_primary);
    }
}

fn arm_restore(clipboard: &mut SystemClipboard) -> RestoreClipboard {
    RestoreClipboard {
        saved_clipboard: clipboard.get(Selection::Clipboard).unwrap_or_default(),
        saved_primary: clipboard.get(Selection::Primary).unwrap_or_default(),
    }
}

fn detect_reader(clipboard: &mut SystemClipboard) -> Option<Reader> {
    if clipboard.set(Selection::Clipboard, PROBE).is_err() {
        return None;
    }
    [Reader::WlPaste, Reader::Xclip]
        .into_iter()
        .find(|reader| tool_exists(reader.binary()) && reader.read(Selection::Clipboard) == PROBE)
}

fn require_clipboard() -> bool {
    std::env::var_os("CC_WALLET_REQUIRE_CLIPBOARD_TEST").is_some()
}

fn skip_or_fail(reason: &str) {
    assert!(
        !require_clipboard(),
        "real-clipboard test required (CC_WALLET_REQUIRE_CLIPBOARD_TEST set) but cannot run: {reason}"
    );
    eprintln!("skipping real-clipboard test: {reason}");
}

#[test]
fn a_copied_phrase_is_visible_to_other_apps_and_a_wipe_removes_it() {
    let _serial = clipboard_guard();
    let mut clipboard = SystemClipboard;
    let _restore = arm_restore(&mut clipboard);
    let Some(reader) = detect_reader(&mut clipboard) else {
        return skip_or_fail("no external reader agrees with arboard's clipboard backend here");
    };

    clipboard
        .set(Selection::Clipboard, PHRASE)
        .expect("the app must be able to copy");

    assert_eq!(
        reader.read(Selection::Clipboard),
        PHRASE,
        "another app must see exactly what we copied"
    );
    assert_eq!(
        clipboard.get(Selection::Clipboard).unwrap().trim(),
        PHRASE,
        "the read-back guard must recognise our own copy, or the wipe never fires"
    );

    clipboard
        .set(Selection::Clipboard, "")
        .expect("the app must be able to clear");
    assert_eq!(
        reader.read(Selection::Clipboard),
        "",
        "after the wipe another app must see nothing"
    );
}

#[test]
fn every_copy_survives_for_another_app_not_just_the_lucky_ones() {
    let _serial = clipboard_guard();
    let mut clipboard = SystemClipboard;
    let _restore = arm_restore(&mut clipboard);
    let Some(reader) = detect_reader(&mut clipboard) else {
        return skip_or_fail("no external reader agrees with arboard's clipboard backend here");
    };

    for round in 0..10 {
        let copied = format!("{PROBE}-{round}");
        clipboard
            .set(Selection::Clipboard, &copied)
            .expect("the app must be able to copy");
        assert_eq!(
            reader.read(Selection::Clipboard),
            copied,
            "copy {round} was gone before another app could read it"
        );
    }
}

#[test]
fn the_primary_selection_is_reachable_and_clearable() {
    let _serial = clipboard_guard();
    let mut clipboard = SystemClipboard;
    let _restore = arm_restore(&mut clipboard);
    let Some(reader) = detect_reader(&mut clipboard) else {
        return skip_or_fail("no external reader agrees with arboard's clipboard backend here");
    };

    clipboard
        .set(Selection::Primary, "absorb abstract")
        .expect("primary must be writable");
    assert_eq!(reader.read(Selection::Primary), "absorb abstract");

    clipboard.set(Selection::Primary, "").expect("clearable");
    assert_eq!(reader.read(Selection::Primary), "");
}
