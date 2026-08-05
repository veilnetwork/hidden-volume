//! The `hv` CLI must not echo a password typed at a terminal
//! (report6 P2).
//!
//! `read_password` was a bare `read_line`, so at an interactive prompt
//! the tty printed every character back and the password stayed in the
//! scrollback of whoever was looking at the screen — on a tool whose
//! whole point is that a container's contents cannot be compelled out
//! of you.
//!
//! ## Why this needs a pty
//!
//! The property only exists when stdin IS a terminal — the fix branches
//! on `IsTerminal` precisely so that the piped form keeps working
//! byte-for-byte — so a test that pipes stdin, which is what every
//! other CLI test does, cannot see it either way. `openpty` gives a
//! real terminal to hand the child, and the master side shows exactly
//! what a user would have seen on screen.
//!
//! Unix only, same as the code it covers: turning echo off on Windows
//! needs `SetConsoleMode`, which is deliberately not implemented (see
//! `EchoOff` in `src/bin/hv.rs`).

#![cfg(all(feature = "cli", unix))]

use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Command, Stdio};

/// A freshly-allocated pseudo-terminal pair.
struct Pty {
    master: std::fs::File,
    slave: OwnedFd,
}

fn openpty() -> Pty {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    // SAFETY: both out-params are valid pointers to `c_int`; the
    // remaining three arguments are documented as optional and null
    // means "defaults".
    let rc = unsafe {
        libc::openpty(
            &raw mut master,
            &raw mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0, "openpty failed: {}", std::io::Error::last_os_error());
    // SAFETY: `openpty` returned success, so both descriptors are open
    // and owned by us.
    unsafe {
        Pty {
            master: std::fs::File::from_raw_fd(master),
            slave: OwnedFd::from_raw_fd(slave),
        }
    }
}

fn scratch_path() -> std::path::PathBuf {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let p = tmp.path().to_owned();
    drop(tmp);
    p
}

/// Run `hv <args>` with the slave end of a pty as stdin/stderr, type
/// `password` once the prompt has appeared, and return everything the
/// master saw — i.e. everything that would have been on a user's
/// screen.
///
/// **Nothing here waits without a deadline.** Every read of the pty and
/// every wait on the child is bounded, because a test that can hang
/// wedges the suite instead of failing it — and the reader thread is
/// deliberately never joined, since joining it is a wait on an fd whose
/// close order this test does not fully control.
fn run_on_a_terminal(args: &[&str], password: &str) -> String {
    let mut session = Session::start(args);
    session.wait_for_prompt();
    session.type_line(password);
    session.wait_for_exit();
    session.transcript()
}

/// How long any single step may take. Generous: these are process
/// spawns and an Argon2 derivation on a machine that may be running the
/// rest of the suite at the same time. Far below libtest's 60 s
/// slow-test warning, so a breach is reported as a failure with a
/// message rather than as a stall.
const STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A child holding one end of a pty, with everything the pty showed
/// accumulating in the background.
struct Session {
    child: std::process::Child,
    master: std::fs::File,
    seen: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    /// A slave fd the SESSION keeps rather than handing to the child,
    /// so a test can read the terminal's attributes after the child is
    /// gone. `take()`n by the one test that needs it; dropped with the
    /// session otherwise, which is what lets the reader thread reach
    /// end-of-transcript.
    observer: Option<OwnedFd>,
}

impl Session {
    fn start(args: &[&str]) -> Self {
        use std::sync::{Arc, Mutex};

        let pty = openpty();
        let child = Command::new(env!("CARGO_BIN_EXE_hv"))
            .args(args)
            .stdin(Stdio::from(pty.slave.try_clone().unwrap()))
            // The prompt goes to stderr; point it at the terminal too,
            // so what we read back is the whole visible transcript.
            .stderr(Stdio::from(pty.slave.try_clone().unwrap()))
            // NOT piped: an unread pipe is one more thing that can
            // block, and no assertion here looks at stdout.
            .stdout(Stdio::null())
            .spawn()
            .expect("spawn hv");

        // Held, not dropped: see `Session::observer`. It is released
        // when the session is, which is when the reader thread reaches
        // end-of-transcript.
        let observer = pty.slave;

        let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
        {
            let seen = Arc::clone(&seen);
            let mut reader = pty.master.try_clone().expect("clone master");
            // Detached on purpose — see the note on `run_on_a_terminal`.
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    // On Linux a master read after the last slave
                    // closes answers EIO rather than EOF; both end the
                    // transcript.
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => seen.lock().unwrap().extend_from_slice(&buf[..n]),
                    }
                }
            });
        }

        Self {
            child,
            master: pty.master,
            seen,
            observer: Some(observer),
        }
    }

    fn transcript(&self) -> String {
        String::from_utf8_lossy(&self.seen.lock().unwrap()).into_owned()
    }

    /// Block until the password prompt shows up on the terminal.
    ///
    /// Required, not politeness: `EchoOff` clears `ECHO` with
    /// `TCSAFLUSH`, which discards input typed but not yet read — that
    /// is the point, so characters entered before the prompt are not
    /// silently taken as part of the password. Writing straight after
    /// `spawn` races the child's `tcsetattr`, and when the test wins
    /// that race its password is thrown away and the child waits for a
    /// line that never comes.
    fn wait_for_prompt(&self) {
        let deadline = std::time::Instant::now() + STEP_TIMEOUT;
        loop {
            let got = self.transcript();
            if got.to_lowercase().contains("password") {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no password prompt on the terminal within {STEP_TIMEOUT:?}; \
                 transcript so far: {got:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn type_line(&mut self, text: &str) {
        self.master.write_all(text.as_bytes()).expect("type");
        self.master.write_all(b"\n").expect("type Enter");
        self.master.flush().ok();
    }

    /// Reap the child, killing it rather than waiting forever.
    fn wait_for_exit(&mut self) {
        let deadline = std::time::Instant::now() + STEP_TIMEOUT;
        loop {
            match self.child.try_wait().expect("try_wait") {
                Some(_) => break,
                None if std::time::Instant::now() >= deadline => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    panic!(
                        "hv did not exit within {STEP_TIMEOUT:?}; transcript: {:?}",
                        self.transcript()
                    );
                },
                None => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        // Give the reader a moment to drain what the child wrote just
        // before exiting. Bounded, and the transcript is only ever read
        // after this.
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// The password must not appear in what the terminal showed.
///
/// A distinctive string, so a match cannot be a coincidence of some
/// other output — and one that would be echoed verbatim if echo were
/// on, which is exactly what happened before this change.
#[test]
fn a_password_typed_at_a_terminal_is_not_echoed() {
    let path = scratch_path();
    let path_str = path.to_str().unwrap().to_owned();

    // Create the container first, over a pipe: no password involved.
    let status = Command::new(env!("CARGO_BIN_EXE_hv"))
        .args(["create", &path_str, "--params", "min", "--replicas", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("hv create");
    assert!(status.success(), "hv create failed");

    const SECRET: &str = "zzUNMISTAKABLEpassword42";
    let transcript = run_on_a_terminal(&["create-space", &path_str], SECRET);

    // Calibration: the prompt DID reach the terminal, so the transcript
    // is a real transcript and not an empty read. Without this, "the
    // password is absent" would be satisfied by capturing nothing.
    assert!(
        transcript.to_lowercase().contains("password"),
        "no prompt in the terminal transcript ({transcript:?}) — this test \
         captured nothing, so its main assertion proves nothing"
    );

    assert!(
        !transcript.contains(SECRET),
        "the password was echoed to the terminal: {transcript:?}"
    );

    let _ = std::fs::remove_file(&path);
}

/// The terminal must be left as it was found.
///
/// `EchoOff` is a guard so that every path out of `read_password`
/// restores `ECHO` — a shell left with echo cleared is a bad way to
/// fail, and the failure outlives the process that caused it. Nothing
/// else in this file would notice: both tests above tear the pty down
/// with the child, so a `Drop` that restored nothing would pass them.
#[test]
fn the_terminal_is_restored_after_the_prompt() {
    let path = scratch_path();
    let path_str = path.to_str().unwrap().to_owned();

    let status = Command::new(env!("CARGO_BIN_EXE_hv"))
        .args(["create", &path_str, "--params", "min", "--replicas", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("hv create");
    assert!(status.success());

    // A slave fd this test keeps, taken before the session hands its
    // copies to the child, so the terminal outlives the child and its
    // attributes can be read afterwards.
    let mut session = Session::start(&["create-space", &path_str]);
    let observer = session.observer.take().expect("observer fd");
    assert!(
        echo_is_on(&observer),
        "a fresh pty should start with ECHO on"
    );

    session.wait_for_prompt();
    session.type_line("restored-check");
    session.wait_for_exit();

    assert!(
        echo_is_on(&observer),
        "the CLI exited with the terminal's ECHO still cleared — the \
         user's shell is left unable to show what they type"
    );

    let _ = std::fs::remove_file(&path);
}

/// Whether `ECHO` is set on the terminal behind `fd`.
fn echo_is_on(fd: &OwnedFd) -> bool {
    use std::os::fd::AsRawFd as _;
    // SAFETY: `fd` is an open terminal descriptor; `tcgetattr` fills
    // the struct and reports failure in its return value.
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::tcgetattr(fd.as_raw_fd(), &raw mut term) };
    assert_eq!(rc, 0, "tcgetattr on the observer fd failed");
    term.c_lflag & libc::ECHO != 0
}

/// …and the space really was created, so echo suppression did not come
/// at the price of the CLI not reading the password at all.
#[test]
fn the_password_still_arrives_when_echo_is_suppressed() {
    let path = scratch_path();
    let path_str = path.to_str().unwrap().to_owned();

    let status = Command::new(env!("CARGO_BIN_EXE_hv"))
        .args(["create", &path_str, "--params", "min", "--replicas", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("hv create");
    assert!(status.success());

    const SECRET: &str = "typed-at-a-tty";
    let _ = run_on_a_terminal(&["create-space", &path_str], SECRET);

    // Open the space the ordinary way — over a pipe — with the password
    // that was typed into the terminal. If the tty path had eaten or
    // mangled a byte, this would not open.
    let mut child = Command::new(env!("CARGO_BIN_EXE_hv"))
        .args(["inspect", &path_str])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hv inspect");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{SECRET}\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "the space typed at the terminal does not open with that password; \
         stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_file(&path);
}
