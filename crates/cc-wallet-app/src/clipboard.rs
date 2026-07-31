use std::time::Duration;

use cc_wallet_domain::normalize_seed;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) fn ct_str_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Selection {
    Clipboard,
    Primary,
}

pub trait ClipboardBackend {
    fn get(&mut self, selection: Selection) -> Result<String, String>;
    fn set(&mut self, selection: Selection, text: &str) -> Result<(), String>;
}

pub fn clipboard_contains_seed(
    current: &str,
    normalized_secret: &str,
    selection: Selection,
) -> bool {
    let current = Zeroizing::new(normalize_seed(current));
    let normalized_secret = Zeroizing::new(normalize_seed(normalized_secret));
    if current.is_empty() {
        return false;
    }
    if ct_str_eq(&current, &normalized_secret) {
        return true;
    }
    let words: Vec<&str> = normalized_secret.split_whitespace().collect();
    let tokens: Vec<&str> = current.split_whitespace().collect();
    let min_run = match selection {
        Selection::Primary => 1,
        Selection::Clipboard => 2,
    };
    if tokens.len() < min_run || words.is_empty() || tokens.len() > words.len() {
        return false;
    }
    words
        .windows(tokens.len())
        .any(|window| window == tokens.as_slice())
}

const CLIPBOARD_OP_TIMEOUT: Duration = Duration::from_secs(2);
const CLIPBOARD_MAX_TEXT_BYTES: usize = 64 * 1024;

fn cap_clipboard_text(mut text: String) -> String {
    if text.len() > CLIPBOARD_MAX_TEXT_BYTES {
        let mut end = CLIPBOARD_MAX_TEXT_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

struct OwnerRequest {
    selection: Selection,
    text: String,
    reply: std::sync::mpsc::Sender<Result<(), String>>,
}

static OWNER: std::sync::Mutex<Option<std::sync::mpsc::Sender<OwnerRequest>>> =
    std::sync::Mutex::new(None);

fn owner_channel() -> std::sync::MutexGuard<'static, Option<std::sync::mpsc::Sender<OwnerRequest>>>
{
    OWNER.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn owner_set(selection: Selection, text: &str) -> Result<(), String> {
    let (reply, replies) = std::sync::mpsc::channel();
    let mut pending = Some(OwnerRequest {
        selection,
        text: text.to_owned(),
        reply,
    });
    {
        let mut owner = owner_channel();
        if let Some(sender) = owner.as_ref()
            && let Err(returned) = sender.send(pending.take().expect("the request is still here"))
        {
            *owner = None;
            pending = Some(returned.0);
        }
        if let Some(request) = pending {
            let sender = spawn_owner();
            sender
                .send(request)
                .map_err(|_| "the clipboard owner stopped before it could copy".to_owned())?;
            *owner = Some(sender);
        }
    }
    match replies.recv_timeout(CLIPBOARD_OP_TIMEOUT) {
        Ok(result) => result,
        Err(_) => {
            *owner_channel() = None;
            Err(format!(
                "clipboard operation did not complete within {}s",
                CLIPBOARD_OP_TIMEOUT.as_secs()
            ))
        }
    }
}

fn spawn_owner() -> std::sync::mpsc::Sender<OwnerRequest> {
    let (sender, requests) = std::sync::mpsc::channel::<OwnerRequest>();
    std::thread::spawn(move || {
        let mut clipboard = match arboard::Clipboard::new() {
            Ok(clipboard) => clipboard,
            Err(error) => {
                let error = error.to_string();
                for request in requests {
                    let _ = request.reply.send(Err(error.clone()));
                }
                return;
            }
        };
        for request in requests {
            let _ = request
                .reply
                .send(apply_set(&mut clipboard, request.selection, &request.text));
        }
    });
    sender
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
))]
fn apply_set(
    clipboard: &mut arboard::Clipboard,
    selection: Selection,
    text: &str,
) -> Result<(), String> {
    use arboard::SetExtLinux;
    clipboard
        .set()
        .clipboard(linux_kind(selection))
        .text(text.to_owned())
        .map_err(|error| error.to_string())
}

#[cfg(not(all(
    unix,
    not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
)))]
fn apply_set(
    clipboard: &mut arboard::Clipboard,
    _selection: Selection,
    text: &str,
) -> Result<(), String> {
    clipboard
        .set_text(text.to_owned())
        .map_err(|error| error.to_string())
}

pub struct SystemClipboard;

impl SystemClipboard {
    fn with_timeout<T, F>(timeout: Duration, op: F) -> Result<T, String>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, String> + Send + 'static,
    {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(op());
        });
        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(_) => Err(format!(
                "clipboard operation did not complete within {}s",
                timeout.as_secs()
            )),
        }
    }

    fn on_clipboard<T, F>(op: F) -> Result<T, String>
    where
        T: Send + 'static,
        F: FnOnce(&mut arboard::Clipboard) -> Result<T, String> + Send + 'static,
    {
        Self::with_timeout(CLIPBOARD_OP_TIMEOUT, move || {
            let mut clipboard = arboard::Clipboard::new().map_err(|error| error.to_string())?;
            op(&mut clipboard)
        })
    }
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
))]
fn linux_kind(selection: Selection) -> arboard::LinuxClipboardKind {
    match selection {
        Selection::Clipboard => arboard::LinuxClipboardKind::Clipboard,
        Selection::Primary => arboard::LinuxClipboardKind::Primary,
    }
}

impl ClipboardBackend for SystemClipboard {
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
    ))]
    fn get(&mut self, selection: Selection) -> Result<String, String> {
        Self::on_clipboard(move |clipboard| {
            use arboard::GetExtLinux;
            match clipboard.get().clipboard(linux_kind(selection)).text() {
                Ok(text) => Ok(cap_clipboard_text(text)),
                Err(arboard::Error::ContentNotAvailable) => Ok(String::new()),
                Err(error) => Err(error.to_string()),
            }
        })
    }

    #[cfg(not(all(
        unix,
        not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
    )))]
    fn get(&mut self, selection: Selection) -> Result<String, String> {
        if selection == Selection::Primary {
            return Ok(String::new());
        }
        Self::on_clipboard(move |clipboard| match clipboard.get_text() {
            Ok(text) => Ok(cap_clipboard_text(text)),
            Err(arboard::Error::ContentNotAvailable) => Ok(String::new()),
            Err(error) => Err(error.to_string()),
        })
    }

    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
    ))]
    fn set(&mut self, selection: Selection, text: &str) -> Result<(), String> {
        owner_set(selection, text)
    }

    #[cfg(not(all(
        unix,
        not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
    )))]
    fn set(&mut self, selection: Selection, text: &str) -> Result<(), String> {
        if selection == Selection::Primary {
            return Ok(());
        }
        owner_set(selection, text)
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct Board {
    pub clipboard: String,
    pub primary: String,
    pub fail_get: bool,
    pub fail_set: bool,
    pub fail_get_selection: Option<Selection>,
    pub fail_set_selection: Option<Selection>,
}

#[cfg(test)]
#[derive(Default, Clone)]
pub struct MemoryClipboard {
    pub board: std::rc::Rc<std::cell::RefCell<Board>>,
}

#[cfg(test)]
impl ClipboardBackend for MemoryClipboard {
    fn get(&mut self, selection: Selection) -> Result<String, String> {
        let board = self.board.borrow();
        if board.fail_get || board.fail_get_selection == Some(selection) {
            return Err("simulated clipboard read failure".to_owned());
        }
        Ok(match selection {
            Selection::Clipboard => board.clipboard.clone(),
            Selection::Primary => board.primary.clone(),
        })
    }

    fn set(&mut self, selection: Selection, text: &str) -> Result<(), String> {
        let mut board = self.board.borrow_mut();
        if board.fail_set || board.fail_set_selection == Some(selection) {
            return Err("simulated clipboard write failure".to_owned());
        }
        match selection {
            Selection::Clipboard => board.clipboard = text.to_owned(),
            Selection::Primary => board.primary = text.to_owned(),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_str_eq_functional_parity() {
        assert!(ct_str_eq("alpha bravo", "alpha bravo"));
        assert!(!ct_str_eq("alpha bravo", "alpha bravx"));
        assert!(!ct_str_eq("alpha", "alpha bravo"));
        assert!(ct_str_eq("", ""));
    }

    #[test]
    fn clipboard_with_timeout_returns_results_and_bounds_a_hang() {
        let ok = SystemClipboard::with_timeout(Duration::from_secs(1), || Ok::<_, String>(7));
        assert_eq!(ok.unwrap(), 7);

        let hung = SystemClipboard::with_timeout(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_secs(30));
            Ok::<_, String>(0)
        });
        assert!(hung.unwrap_err().contains("did not complete"));

        let err = SystemClipboard::with_timeout(Duration::from_secs(1), || {
            Err::<u8, _>("backend failure".to_owned())
        });
        assert_eq!(err.unwrap_err(), "backend failure");
    }

    const PHRASE: &str =
        "abandon ability able about above absent absorb abstract absurd abuse access accident";

    #[test]
    fn seed_predicate_matches_the_whole_phrase_on_either_selection() {
        for selection in [Selection::Clipboard, Selection::Primary] {
            assert!(clipboard_contains_seed(PHRASE, PHRASE, selection));
            assert!(clipboard_contains_seed(
                " abandon\nability  able about above absent absorb abstract absurd abuse access accident ",
                PHRASE,
                selection
            ));
        }
    }

    #[test]
    fn a_single_word_matches_primary_but_not_the_clipboard() {
        assert!(clipboard_contains_seed(
            "absorb",
            PHRASE,
            Selection::Primary
        ));
        assert!(clipboard_contains_seed(
            "  absorb\n",
            PHRASE,
            Selection::Primary
        ));
        assert!(!clipboard_contains_seed(
            "absorb",
            PHRASE,
            Selection::Clipboard
        ));
    }

    #[test]
    fn a_contiguous_in_order_run_matches_both_selections() {
        for selection in [Selection::Clipboard, Selection::Primary] {
            assert!(clipboard_contains_seed(
                "able about above",
                PHRASE,
                selection
            ));
        }
    }

    #[test]
    fn out_of_order_repeated_or_foreign_text_matches_neither() {
        for selection in [Selection::Clipboard, Selection::Primary] {
            assert!(
                !clipboard_contains_seed("about able above", PHRASE, selection),
                "out-of-order words are not a contiguous run"
            );
            assert!(
                !clipboard_contains_seed("absorb absorb", PHRASE, selection),
                "a repetition that is not adjacent in the phrase never matches"
            );
            assert!(!clipboard_contains_seed("absorb hello", PHRASE, selection));
            assert!(!clipboard_contains_seed("hello world", PHRASE, selection));
            assert!(!clipboard_contains_seed("", PHRASE, selection));
            assert!(!clipboard_contains_seed("   ", PHRASE, selection));
        }
    }
}
