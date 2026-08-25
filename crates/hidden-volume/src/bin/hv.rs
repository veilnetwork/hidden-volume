//! `hv` — command-line utility for hidden-volume container files.
//!
//! Build with: `cargo build --features cli --release`
//! Install:    `cargo install --path . --features cli`
//!
//! Subcommands:
//! - `info`           — print public header info (no password needed)
//! - `create`         — create an empty container
//! - `create-space`   — create a new space (password from stdin)
//! - `inspect`        — list namespaces with entry counts (password from stdin)
//! - `get`            — read one KV value (password + namespace + key)
//! - `put`            — write one KV value (password + namespace + key + value)
//! - `verify`         — walk the Merkle tree, report integrity status
//! - `dump-stats`     — print aggregated SpaceStats (commit_seq, history
//!   len, owned-chunk count, per-namespace counts)
//! - `repack`         — copy live state to a new container, dropping
//!   anything not unlocked by the supplied passwords
//!
//! Passwords are read from **stdin** (one line per password, trailing
//! newline trimmed). Use `echo password | hv create-space store.bin`
//! for quick command-line scripting. There is intentionally no env-var
//! fallback: env vars are visible to other UID processes via
//! `/proc/PID/environ` and surface in `ps -e` on some kernels —
//! incompatible with the compelled-key deniability story. For the same
//! reason there is no `--password` flag: an argument is world-readable
//! in `ps` for the life of the process.
//!
//! When stdin is a **terminal**, echo is suppressed while a password is
//! typed — for the single-password prompts (report6 P2) and for
//! `repack`, which collects one per space (report7 P1) — on Unix and on
//! Windows alike; see `EchoOff`. A piped or redirected password takes
//! exactly the path it always did.
//!
//! Stdin is also bounded: `MAX_PASSWORD_LINE` per line and
//! `MAX_PASSWORDS` in total, so a file redirected here by mistake is
//! refused rather than buffered.

use std::io::{BufRead, Read as _, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use hidden_volume::container::{ContainerOptions, RepackOptions};
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::space::index::Namespace;
use hidden_volume::{Container, Result};

#[derive(Parser, Debug)]
#[command(
    name = "hv",
    version,
    about = "Hidden-volume container CLI — debug / migration / scripting utility.",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print public header info (no password needed).
    Info { path: PathBuf },

    /// Create an empty container.
    Create {
        path: PathBuf,
        /// Argon2 cost preset.
        #[arg(long, default_value = "default", value_parser = ["min", "light", "default", "heavy"])]
        params: String,
        /// Initial garbage chunks (decoy size). 256 = 1 MiB.
        #[arg(long, default_value_t = 0)]
        initial_garbage: u64,
        /// Number of Superblock replicas per commit (1-255). Default 3.
        #[arg(long, default_value_t = 3)]
        replicas: u8,
    },

    /// Create a new space (password from stdin).
    CreateSpace { path: PathBuf },

    /// List namespaces with entry counts (password from stdin).
    Inspect { path: PathBuf },

    /// Read one KV value (password from stdin).
    Get {
        path: PathBuf,
        /// Namespace ID (1=SETTINGS, 2=CONTACTS, 3=MESSAGE_LOG, 4=MEDIA, ...)
        namespace: u8,
        /// Key (UTF-8 bytes).
        key: String,
    },

    /// Write one KV value (password from stdin).
    ///
    /// `value` is read from positional argv by default — convenient for
    /// scripting non-secret values, but bear in mind argv is visible
    /// via `ps -e` to other UID processes. For secret values, omit the
    /// positional `value` and pass `--value-stdin`; the value is then
    /// read as the **second** stdin line (after the password line).
    Put {
        path: PathBuf,
        namespace: u8,
        key: String,
        /// Positional value bytes. Mutually exclusive with `--value-stdin`.
        #[arg(
            conflicts_with = "value_stdin",
            required_unless_present = "value_stdin"
        )]
        value: Option<String>,
        /// Read value bytes from stdin (second line, after password)
        /// instead of argv. Audit F4 (2026-05-03) hardening — keeps
        /// secret values out of `ps -e`.
        #[arg(long, conflicts_with = "value")]
        value_stdin: bool,
    },

    /// Walk the Merkle tree under the given password and report integrity
    /// status. Read-only — uses LOCK_SH (concurrent-readers safe).
    Verify { path: PathBuf },

    /// Print aggregated [`hidden_volume::space::SpaceStats`] for one space:
    /// commit_seq, commit_history length, owned-chunk count, per-namespace
    /// entry counts. Read-only.
    DumpStats { path: PathBuf },

    /// Repack a container, dropping any space whose password is not supplied.
    /// Reads passwords from stdin, one per line, ending with EOF.
    Repack { source: PathBuf, dest: PathBuf },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hv: {e}");
            ExitCode::FAILURE
        },
    }
}

fn run(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Info { path } => cmd_info(path),
        Cmd::Create {
            path,
            params,
            initial_garbage,
            replicas,
        } => cmd_create(path, &params, initial_garbage, replicas),
        Cmd::CreateSpace { path } => cmd_create_space(path),
        Cmd::Inspect { path } => cmd_inspect(path),
        Cmd::Get {
            path,
            namespace,
            key,
        } => cmd_get(path, namespace, key),
        Cmd::Put {
            path,
            namespace,
            key,
            value,
            value_stdin,
        } => cmd_put(path, namespace, key, value, value_stdin),
        Cmd::Verify { path } => cmd_verify(path),
        Cmd::DumpStats { path } => cmd_dump_stats(path),
        Cmd::Repack { source, dest } => cmd_repack(source, dest),
    }
}

// --- helpers ---

/// Read a password from stdin (one line, trailing newline trimmed).
///
/// Audit F3 (2026-05-03): the previous `HV_PASSWORD` env-var fallback
/// was removed. Environment variables are visible to other UID
/// processes via `/proc/PID/environ` and surface in `ps -e` on some
/// kernels — using them for passwords weakens compelled-key
/// deniability and adds a foot-gun for scripting. Pipe the password
/// in via stdin instead: `echo password | hv create-space store.bin`.
///
/// Audit pass 17 F: returns `Zeroizing<Vec<u8>>` so the heap buffer
/// scrubs on drop. The intermediate `String` is a transient that
/// `into_bytes` consumes; we cannot wrap a `String` in `Zeroizing`
/// directly (no `Zeroize` impl), but the `String` lives only until
/// the end-of-function and its bytes are moved (not copied) into the
/// returned `Vec<u8>`.
///
/// **Echo is suppressed when stdin is a terminal** (report6 P2). It was
/// a bare `read_line`, so a password typed at a prompt was printed back
/// by the tty and stayed in the scrollback of whoever was looking at
/// the screen — on a tool whose whole point is that a container's
/// contents cannot be compelled out of you.
///
/// The branch is on `IsTerminal` and nothing else, so a piped or
/// redirected password — `echo pw | hv …`, which is the documented
/// scripting idiom and the one every test uses — takes byte-for-byte
/// the same path it always did. There is no terminal to change the mode
/// of in that case, and changing behaviour there would break scripts
/// for no privacy gain.
fn read_password(prompt: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use std::io::IsTerminal as _;

    eprint!("{prompt}");
    std::io::stderr().flush().ok();

    let interactive = std::io::stdin().is_terminal();
    let echo_off = if interactive { EchoOff::engage() } else { None };

    let stdin = std::io::stdin();
    // Bounded: `read_line` here grew a `String` until a newline arrived, so a
    // pipe that never sent one allocated without limit — and left every
    // intermediate buffer, password inside, on the heap (report14 HV14-M4).
    // The repack path two functions down has always read this way.
    let read = read_capped_line(&mut stdin.lock(), MAX_PASSWORD_LINE, "password from stdin");
    // Restore the terminal BEFORE anything can return early, so a read
    // error does not leave the user's shell with echo off.
    drop(echo_off);
    let line = read?;
    if interactive {
        // The Enter that ended the line was not echoed either, so
        // without this the next thing written lands on the prompt's
        // own line.
        eprintln!();
    }
    Ok(line.unwrap_or_else(|| zeroize::Zeroizing::new(Vec::new())))
}

/// Terminal echo, off for as long as this value lives.
///
/// A guard rather than a pair of calls so that every early return
/// between engage and drop — a read error, a panic — still restores the
/// caller's terminal. Leaving a shell with `ECHO` cleared is a bad way
/// to fail.
///
/// **Unix and Windows.** Unix clears `ECHO` with `tcsetattr`; Windows
/// clears `ENABLE_ECHO_INPUT` with `SetConsoleMode`. The Windows arm
/// was omitted when this guard was written, on the grounds that this
/// host could not compile or run it — but `hv.exe` is built and shipped
/// in every release, and `windows-release-gate.yml` already runs this
/// crate's tests on a Windows runner. There was a place to compile and
/// execute it; it just was not here. Until it was written, the shipped
/// Windows binary printed passwords on screen (report7 P1).
///
/// Everywhere else — a platform that is neither — `engage` answers
/// `None` and the read behaves as an ordinary `read_line`, which is
/// what every platform did before.
///
/// Not signal-safe: a SIGINT between engage and drop leaves the
/// terminal with echo off until `stty sane`. That is the same hole
/// `getpass(3)` and every password prompt built on `tcsetattr` has, and
/// closing it means installing a handler this binary has no other
/// reason to own.
struct EchoOff {
    #[cfg(unix)]
    saved: libc::termios,
    #[cfg(windows)]
    saved: u32,
}

/// The console mode `mode` with echo cleared.
///
/// Split out from the syscall wiring so the one piece of *logic* on the
/// Windows path can be tested on every platform, including the hosts
/// that cannot run a Windows console. `ENABLE_LINE_INPUT` is
/// deliberately left alone: with line input on and echo off, `ReadFile`
/// still does the usual line editing while showing nothing, which is
/// exactly what a password prompt wants.
#[cfg(any(windows, test))]
const fn console_mode_without_echo(mode: u32) -> u32 {
    // Same value as `windows_sys::Win32::System::Console::ENABLE_ECHO_INPUT`,
    // written out so this function compiles — and is tested — off Windows.
    const ENABLE_ECHO_INPUT: u32 = 0x0004;
    mode & !ENABLE_ECHO_INPUT
}

impl EchoOff {
    /// Clear `ECHO` on stdin, returning the guard that restores it.
    /// `None` when there is nothing to do or the attempt failed — the
    /// caller then reads with echo on, which is what it did before, and
    /// is a better outcome than refusing to read at all.
    #[cfg(unix)]
    fn engage() -> Option<Self> {
        use std::os::fd::AsRawFd as _;
        let fd = std::io::stdin().as_raw_fd();
        // SAFETY: `fd` is stdin, open for the process's lifetime.
        // `tcgetattr` writes a `termios` through the pointer and
        // reports failure in its return value; `term` is only read
        // after a success.
        let mut term: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &raw mut term) } != 0 {
            return None;
        }
        let saved = term;
        term.c_lflag &= !libc::ECHO;
        // TCSAFLUSH, not TCSANOW: it discards input typed but not yet
        // read, so characters entered before the prompt appeared are
        // not silently taken as part of the password.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw const term) } != 0 {
            return None;
        }
        Some(Self { saved })
    }

    /// Clear `ENABLE_ECHO_INPUT` on the console attached to stdin.
    ///
    /// `None` on every failure, which includes the ordinary case of
    /// stdin not being a console at all: `GetConsoleMode` fails on a
    /// pipe or a redirected file, and the caller then reads exactly as
    /// it did before. That path is the one CI exercises, since a
    /// GitHub-hosted runner gives the test process a pipe.
    #[cfg(windows)]
    fn engage() -> Option<Self> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
        };

        // SAFETY: `GetStdHandle` takes a constant and returns a handle
        // the process already owns; it is not ours to close.
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut mode: u32 = 0;
        // SAFETY: `handle` is a valid stdin handle and `mode` is a live
        // `u32`; the call reports failure in its return value and only
        // writes through the pointer on success.
        if unsafe { GetConsoleMode(handle, &raw mut mode) } == 0 {
            // Not a console — a pipe or a file. Nothing to suppress.
            return None;
        }
        // SAFETY: same handle, and the mode differs from the one just
        // read only in the echo bit.
        if unsafe { SetConsoleMode(handle, console_mode_without_echo(mode)) } == 0 {
            return None;
        }
        Some(Self { saved: mode })
    }

    #[cfg(not(any(unix, windows)))]
    fn engage() -> Option<Self> {
        None
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            let fd = std::io::stdin().as_raw_fd();
            // SAFETY: same fd, and `saved` is the exact struct
            // `tcgetattr` produced for it.
            unsafe {
                libc::tcsetattr(fd, libc::TCSAFLUSH, &raw const self.saved);
            }
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Console::{
                GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
            };
            // SAFETY: the guard only exists when `engage` succeeded, so
            // stdin is a console and `saved` is the mode it reported.
            unsafe {
                let handle = GetStdHandle(STD_INPUT_HANDLE);
                SetConsoleMode(handle, self.saved);
            }
        }
    }
}

/// Longest accepted password line, in bytes.
///
/// Not a policy on how long a password may be — it is a bound on how
/// much a single unterminated line can make this process allocate.
/// Without one, `hv repack < /dev/zero` grows a buffer until the
/// machine gives out. 1 KiB is far past any passphrase a human types
/// and far short of anything worth worrying about.
const MAX_PASSWORD_LINE: usize = 1024;

/// Most passwords accepted from one stdin.
///
/// One line per space in the container, and a repack that names more
/// spaces than this is a mistake — a stray file redirected into stdin,
/// most likely — not a request. Bounded for the same reason as the line
/// length: every accepted line is held in memory at once.
const MAX_PASSWORDS: usize = 256;

/// Read one password per line until EOF.
///
/// **Echo is suppressed when stdin is a terminal**, for the same reason
/// as in [`read_password`] and by the same guard (report7 P1). This one
/// mattered more and was missed: `hv repack` *prompts* for interactive
/// use — "Reading passwords from stdin (one per line, EOF to end)" is an
/// invitation, not a warning — and what it collects is the password to
/// EVERY space in the container. All of them went into the terminal
/// scrollback together.
fn read_all_passwords() -> Result<Vec<zeroize::Zeroizing<Vec<u8>>>> {
    use std::io::IsTerminal as _;

    let interactive = std::io::stdin().is_terminal();
    let echo_off = if interactive { EchoOff::engage() } else { None };

    let stdin = std::io::stdin();
    let out = read_passwords_from(stdin.lock());

    // Restore before any early return, so a rejected line does not leave
    // the user's shell unable to show what they type.
    drop(echo_off);
    if interactive {
        // None of the newlines the user typed were echoed.
        eprintln!();
    }
    out
}

/// The parsing half of [`read_all_passwords`], over any reader.
///
/// Split out so the caps below are testable without a terminal and
/// without a subprocess.
/// Read one line, refusing anything past `cap` bytes.
///
/// `take(cap + 1)` and then `read_until`, so a line that is too long is
/// DETECTED rather than buffered. That is the difference from `read_line`,
/// which grows its buffer until a newline arrives — a pipe that never sends
/// one allocates without bound, and every growth step leaves the previous
/// buffer, secret still in it, on the heap for the allocator to hand out
/// whenever it likes (report14 HV14-M4).
///
/// `Ok(None)` is end of input with nothing read. The trailing newline (and a
/// carriage return before it) is removed; the bytes come back in `Zeroizing`
/// because they are secret from the first read, not from the moment they are
/// accepted.
///
/// `what` names the input in the error, because "a line is too long" is not
/// an answer anybody can act on.
fn read_capped_line(
    reader: &mut impl BufRead,
    cap: usize,
    what: &str,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    let mut buf = zeroize::Zeroizing::new(Vec::<u8>::with_capacity(cap + 1));
    let n = reader
        .take(cap as u64 + 1)
        .read_until(b'\n', &mut buf)
        .map_err(|e| {
            hidden_volume::Error::Io(std::io::Error::other(format!("read {what}: {e}")))
        })?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    } else if buf.len() > cap {
        // Filled the whole allowance without reaching a newline.
        return Err(hidden_volume::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("hv: {what} exceeds {cap} bytes"),
        )));
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    Ok(Some(buf))
}

fn read_passwords_from(mut reader: impl BufRead) -> Result<Vec<zeroize::Zeroizing<Vec<u8>>>> {
    let mut out: Vec<zeroize::Zeroizing<Vec<u8>>> = Vec::new();
    loop {
        // `Zeroizing`: these bytes are password material from the first
        // read, not from the moment they are accepted.
        let mut buf = zeroize::Zeroizing::new(Vec::<u8>::new());
        // Read at most one byte more than a line may hold, so a line
        // that is too long is *detected* rather than *buffered*.
        let n = (&mut reader)
            .take(MAX_PASSWORD_LINE as u64 + 1)
            .read_until(b'\n', &mut buf)
            .map_err(|e| {
                hidden_volume::Error::Io(std::io::Error::other(format!(
                    "read password from stdin: {e}"
                )))
            })?;
        if n == 0 {
            return Ok(out);
        }
        if buf.last() == Some(&b'\n') {
            buf.pop();
        } else if buf.len() > MAX_PASSWORD_LINE {
            // Filled the whole allowance without reaching a newline.
            return Err(hidden_volume::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("hv: a password line exceeds {MAX_PASSWORD_LINE} bytes"),
            )));
        }
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        if buf.is_empty() {
            continue;
        }
        if out.len() == MAX_PASSWORDS {
            return Err(hidden_volume::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("hv: more than {MAX_PASSWORDS} passwords on stdin"),
            )));
        }
        out.push(buf);
    }
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        // `write!` to a String is infallible — same idiom as the FFI
        // crate's `hex` (audit pass 12: avoid the per-byte `format!`
        // intermediate `String` allocation that the previous
        // `push_str(&format!("{byte:02x}"))` did).
        let _ = write!(s, "{byte:02x}");
    }
    s
}

fn parse_params(s: &str) -> Argon2Params {
    // clap's `value_parser = ["min", "light", "default", "heavy"]` on
    // the `--params` flag rejects everything else before reaching
    // here. Audit F7 (2026-05-03): make the contract explicit so a
    // future clap-config drift doesn't silently fall through to
    // DEFAULT on unrecognized input.
    match s {
        "min" => Argon2Params::MIN,
        "light" => Argon2Params::LIGHT,
        "default" => Argon2Params::DEFAULT,
        "heavy" => Argon2Params::HEAVY,
        other => unreachable!("clap value_parser should reject {other:?}"),
    }
}

fn ns_name(ns: u8) -> &'static str {
    match ns {
        1 => "SETTINGS",
        2 => "CONTACTS",
        3 => "MESSAGE_LOG",
        4 => "MEDIA",
        _ => "(custom)",
    }
}

// --- commands ---

fn cmd_info(path: PathBuf) -> Result<()> {
    let c = Container::open_readonly(&path)?;
    let h = c.header();
    let p = c.params();
    let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    println!("file:         {}", path.display());
    println!(
        "size:         {} bytes ({:.2} MiB)",
        bytes,
        bytes as f64 / (1024.0 * 1024.0)
    );
    println!("salt:         {}", hex(&h.salt));
    // v3: container_id is derived per-space from the master key, no
    // longer stored in the cleartext header. To see the per-space
    // container_id, open the space.
    println!(
        "argon2:       m={} KiB, t={} iters, p={} lanes, version={}",
        p.m_cost_kib, p.t_cost, p.p_cost, p.version
    );
    println!("readonly:     {}", c.is_readonly());
    Ok(())
}

fn cmd_create(path: PathBuf, params: &str, initial_garbage: u64, replicas: u8) -> Result<()> {
    let options = ContainerOptions {
        argon2: parse_params(params),
        initial_garbage_chunks: initial_garbage,
        padding_policy: hidden_volume::padding::PaddingPolicy::DEFAULT,
        superblock_replicas: replicas,
    };
    Container::create_with_options(&path, options)?;
    println!("created: {}", path.display());
    Ok(())
}

fn cmd_create_space(path: PathBuf) -> Result<()> {
    let pw = read_password("password: ")?;
    let mut c = Container::open(&path)?;
    let _s = c.create_space(&pw)?;
    println!("space created");
    Ok(())
}

fn cmd_inspect(path: PathBuf) -> Result<()> {
    let pw = read_password("password: ")?;
    // Read-only: `inspect` reports what is in a container and must not be a
    // way to change it. A writable open runs the post-open vacuum and the
    // checkpoint self-heal, so looking at a container rewrote it — the one
    // thing a diagnostic command must never do to evidence.
    let mut c = Container::open_readonly(&path)?;
    let mut s = c.open_space(&pw)?;
    println!("commit_seq: {}", s.commit_seq());
    let namespaces = s.list_namespaces()?;
    if namespaces.is_empty() {
        println!("namespaces: (none)");
        return Ok(());
    }
    println!("namespaces:");
    for ns in namespaces {
        let count = s.count(ns)?;
        println!(
            "  {:3} {:<12} {} entries",
            ns.as_u8(),
            ns_name(ns.as_u8()),
            count
        );
    }
    Ok(())
}

fn cmd_get(path: PathBuf, namespace: u8, key: String) -> Result<()> {
    let pw = read_password("password: ")?;
    let mut c = Container::open_readonly(&path)?;
    let mut s = c.open_space(&pw)?;
    match s.get(Namespace(namespace), key.as_bytes())? {
        Some(v) => match std::str::from_utf8(&v) {
            Ok(text) => println!("{text}"),
            Err(_) => println!("{}", hex(&v)),
        },
        None => {
            eprintln!("hv: key not found");
            std::process::exit(2);
        },
    }
    Ok(())
}

fn cmd_put(
    path: PathBuf,
    namespace: u8,
    key: String,
    value: Option<String>,
    value_stdin: bool,
) -> Result<()> {
    // Read password as first stdin line (existing contract).
    let pw = read_password("password: ")?;
    // If `--value-stdin`, read value as the second stdin line.
    // Otherwise the value is on argv (clap enforces exactly one).
    //
    // Audit pass 17 F: scrub the heap copy of the secret value on
    // function exit. Argv-supplied values are *already* visible via
    // `/proc/PID/cmdline` to other UIDs (use `--value-stdin` to
    // avoid that — `hv put --help` documents the flag), but we
    // still scrub the in-process copy to avoid post-drop heap
    // residue.
    let value_bytes: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(if value_stdin {
        // Bounded by what the core will accept anyway: a value past
        // `MAX_VALUE_LEN` is refused by `tx.put`, so reading gigabytes to
        // find that out is pure loss — and it is the caller's secret being
        // grown across the heap while it happens (report14 HV14-M4).
        let stdin = std::io::stdin();
        let line = read_capped_line(
            &mut stdin.lock(),
            hidden_volume::space::index::MAX_VALUE_LEN,
            "value from stdin",
        )?;
        line.map(|b| b.to_vec()).unwrap_or_default()
    } else {
        // clap's `required_unless_present` guarantees `value` is Some
        // when `--value-stdin` is absent. If it isn't, that's a clap
        // schema regression — surface as Internal rather than panic.
        value
            .ok_or(hidden_volume::Error::Internal(
                "clap should reject put without value or --value-stdin",
            ))?
            .into_bytes()
    });
    let mut c = Container::open(&path)?;
    let mut s = c.open_space(&pw)?;
    let mut tx = s.begin_tx();
    tx.put(Namespace(namespace), key.as_bytes(), &value_bytes)?;
    tx.commit()?;
    Ok(())
}

fn cmd_verify(path: PathBuf) -> Result<()> {
    let pw = read_password("password: ")?;
    let mut c = Container::open_readonly(&path)?;
    let mut s = c.open_space(&pw)?;
    let r = s.verify_integrity()?;
    println!("namespaces_verified: {}", r.namespaces_verified);
    println!("chunks_verified:     {}", r.chunks_verified);
    println!("max_depth:           {}", r.max_depth);
    println!("status:              ok");
    Ok(())
}

fn cmd_dump_stats(path: PathBuf) -> Result<()> {
    let pw = read_password("password: ")?;
    let mut c = Container::open_readonly(&path)?;
    let mut s = c.open_space(&pw)?;
    let stats = s.stats()?;
    println!("commit_seq:          {}", stats.commit_seq);
    println!("commit_history_len:  {}", stats.commit_history_len);
    println!("owned_chunk_count:   {}", stats.owned_chunk_count);
    println!("total_slot_count:    {}", stats.total_slot_count);
    println!(
        "utilization_ratio:   {:.3}  ({:.1}% live)",
        stats.utilization_ratio(),
        stats.utilization_ratio() * 100.0,
    );
    println!("total_entries:       {}", stats.total_entries());
    if stats.namespace_counts.is_empty() {
        println!("namespaces:          (none)");
    } else {
        println!("namespaces:");
        for (ns, count) in &stats.namespace_counts {
            println!(
                "  {:3} {:<12} {} entries",
                ns.as_u8(),
                ns_name(ns.as_u8()),
                count
            );
        }
    }
    Ok(())
}

fn cmd_repack(source: PathBuf, dest: PathBuf) -> Result<()> {
    eprintln!("Reading passwords from stdin (one per line, EOF to end):");
    let passwords = read_all_passwords()?;
    if passwords.is_empty() {
        // Audit 2026-05-28: input-validation failure (user piped an
        // empty stdin), not an invariant violation. `Error::Internal`
        // is reserved for crate-internal bugs; surface this as an I/O
        // input error with a CLI-actionable message instead.
        return Err(hidden_volume::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "hv repack: stdin contained no passwords; pipe one password per line and end with EOF",
        )));
    }
    let pw_refs: Vec<&[u8]> = passwords.iter().map(|p| p.as_slice()).collect();
    // `RepackOptions::default()` carries the SOURCE's Argon2 cost and
    // padding policy over to the destination (audit HV-09) — a repack
    // from the CLI is maintenance, and this subcommand has no flag with
    // which to ask for a re-parameterisation, so it must not perform one.
    Container::repack(&source, &dest, &pw_refs, RepackOptions::default())?;
    println!("repacked: {} → {}", source.display(), dest.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- report7 P1: the caps on what stdin may hand us ----

    fn collect(input: &[u8]) -> Result<Vec<String>> {
        let got = read_passwords_from(std::io::Cursor::new(input.to_vec()))?;
        Ok(got
            .iter()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect())
    }

    /// A line that is too long is DETECTED, not buffered.
    ///
    /// `read_line` grows its buffer until a newline arrives, so a pipe that
    /// never sends one allocates without bound — and every growth step leaves
    /// the previous buffer, the caller's password or value still in it, on the
    /// heap for the allocator to hand out whenever it likes. The repack path
    /// had always read within a cap; the password prompt and `--value-stdin`
    /// had not (report14 HV14-M4).
    #[test]
    fn a_capped_read_refuses_a_line_instead_of_growing_for_it() {
        // Well under the cap: unchanged, newline stripped.
        let mut small = std::io::Cursor::new(b"hunter2\n".to_vec());
        let got = read_capped_line(&mut small, 16, "password")
            .unwrap()
            .unwrap();
        assert_eq!(&got[..], b"hunter2");

        // Exactly at the cap, no newline at all: accepted, because the whole
        // line fits what the caller allows.
        let mut exact = std::io::Cursor::new(vec![b'x'; 16]);
        let got = read_capped_line(&mut exact, 16, "password")
            .unwrap()
            .unwrap();
        assert_eq!(got.len(), 16);

        // One byte past it: refused, and the error says what and how much.
        let mut over = std::io::Cursor::new(vec![b'x'; 17]);
        let err = read_capped_line(&mut over, 16, "password").unwrap_err();
        let text = format!("{err}");
        assert!(
            text.contains("password"),
            "the error must name the input: {text}"
        );
        assert!(text.contains("16"), "and the limit: {text}");

        // A pipe with no newline in sight is refused after the cap, not read
        // to its end — the allocation is what this bounds.
        let mut endless = std::io::Cursor::new(vec![b'x'; 4 * 1024 * 1024]);
        assert!(read_capped_line(&mut endless, 1024, "password").is_err());
        assert_eq!(
            endless.position(),
            1025,
            "it must stop at the allowance; reading further is the unbounded \
             allocation this exists to prevent"
        );

        // Nothing at all is end of input, not an empty password.
        let mut empty = std::io::Cursor::new(Vec::<u8>::new());
        assert!(
            read_capped_line(&mut empty, 16, "password")
                .unwrap()
                .is_none()
        );

        // CRLF is tolerated, as everywhere else in this file.
        let mut crlf = std::io::Cursor::new(b"pw\r\n".to_vec());
        let got = read_capped_line(&mut crlf, 16, "password")
            .unwrap()
            .unwrap();
        assert_eq!(&got[..], b"pw");
    }

    /// The value cap is the core's own, so the CLI refuses exactly what the
    /// container would have refused — and refuses it before reading it.
    #[test]
    fn the_value_cap_is_the_one_the_core_enforces() {
        assert_eq!(hidden_volume::space::index::MAX_VALUE_LEN, 2048);
    }

    #[test]
    fn ordinary_input_is_unchanged() {
        // The shape every script and every test uses must keep working
        // byte-for-byte: blank lines skipped, CRLF tolerated, no
        // trailing-newline required.
        assert_eq!(collect(b"a\nb\n").unwrap(), vec!["a", "b"]);
        assert_eq!(collect(b"a\r\nb\r\n").unwrap(), vec!["a", "b"]);
        assert_eq!(collect(b"a\n\n\nb").unwrap(), vec!["a", "b"]);
        assert_eq!(collect(b"").unwrap(), Vec::<String>::new());
    }

    /// The caps are BOUNDS, and a bound has to be an absolute number.
    ///
    /// Stated separately, and first, because the two tests below phrase
    /// their inputs in terms of the constants — so raising a constant
    /// raises the probe along with it and those tests go on passing at
    /// any size. A cap of `usize::MAX` satisfies both of them and bounds
    /// nothing; break-checking found exactly that. These two assertions
    /// are what actually holds the values down. The ceilings are loose
    /// on purpose: a deliberate adjustment stays easy, an accidental
    /// removal does not.
    #[test]
    fn the_caps_are_actually_small() {
        // Bound through locals rather than asserting on the constants
        // directly: `clippy::assertions_on_constants` would otherwise
        // push this into a `const` block, and a build error names no
        // test. A raised cap should fail HERE, by name.
        let line = MAX_PASSWORD_LINE;
        let count = MAX_PASSWORDS;
        assert!(
            line <= 4096,
            "a {line}-byte password line is not a bound on anything"
        );
        assert!(
            count <= 1024,
            "{count} passwords is not a bound on anything"
        );
    }

    #[test]
    fn a_password_line_may_not_exceed_its_cap() {
        // A line one byte inside the cap is still a password...
        let ok = vec![b'x'; MAX_PASSWORD_LINE];
        assert_eq!(collect(&ok).unwrap().len(), 1);

        // ...and one byte past it is refused rather than buffered. The
        // point is that the refusal happens without reading the rest:
        // before this cap, `hv repack < /dev/zero` grew a single line
        // until the machine gave out.
        let mut too_long = vec![b'x'; MAX_PASSWORD_LINE + 1];
        too_long.push(b'\n');
        let err = collect(&too_long).expect_err("an over-long line must be refused");
        assert!(
            err.to_string().contains("exceeds"),
            "unhelpful message: {err}"
        );

        // And an ABSOLUTE input, owing nothing to the constant: one
        // mebibyte on a single line is not a password under any cap
        // this program should ship with.
        let a_megabyte = vec![b'x'; 1024 * 1024];
        collect(&a_megabyte).expect_err("a 1 MiB line must be refused whatever the cap says");
    }

    #[test]
    fn the_number_of_passwords_is_capped() {
        let at_cap: Vec<u8> = (0..MAX_PASSWORDS)
            .flat_map(|i| format!("pw{i}\n").into_bytes())
            .collect();
        assert_eq!(collect(&at_cap).unwrap().len(), MAX_PASSWORDS);

        let over_cap: Vec<u8> = (0..MAX_PASSWORDS + 1)
            .flat_map(|i| format!("pw{i}\n").into_bytes())
            .collect();
        let err = collect(&over_cap).expect_err("more passwords than the cap must be refused");
        assert!(
            err.to_string().contains("more than"),
            "unhelpful message: {err}"
        );

        // Absolute, as above: four thousand lines is a file someone
        // redirected by mistake, not a container's worth of spaces.
        let four_thousand: Vec<u8> = (0..4096)
            .flat_map(|i| format!("pw{i}\n").into_bytes())
            .collect();
        collect(&four_thousand).expect_err("4096 passwords must be refused whatever the cap says");
    }

    // ---- report7 P1: the Windows echo branch ----

    /// The one piece of logic on the Windows path, checked on every
    /// platform.
    ///
    /// `SetConsoleMode` cannot be called on a host without a console, and
    /// the CI runner that CAN call it hands the test process a pipe. What
    /// remains testable everywhere is the mode arithmetic — and getting it
    /// wrong is the failure that matters, because clearing the wrong bit
    /// would either leave echo on (the bug this closes) or disable line
    /// editing and leave the prompt unusable.
    #[test]
    fn clearing_echo_leaves_every_other_console_bit_alone() {
        const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
        const ENABLE_LINE_INPUT: u32 = 0x0002;
        const ENABLE_ECHO_INPUT: u32 = 0x0004;

        // The mode a Windows console starts with, echo included.
        let typical = ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT;
        let suppressed = console_mode_without_echo(typical);

        assert_eq!(
            suppressed & ENABLE_ECHO_INPUT,
            0,
            "echo is still enabled — the password would be printed"
        );
        assert_eq!(
            suppressed,
            typical & !ENABLE_ECHO_INPUT,
            "a bit other than ENABLE_ECHO_INPUT changed"
        );
        // Line editing must survive: with it cleared the prompt stops
        // handling backspace and Enter, which is a broken prompt rather
        // than a private one.
        assert_ne!(
            suppressed & ENABLE_LINE_INPUT,
            0,
            "line input was cleared along with echo"
        );

        // Idempotent, and a no-op on a mode that never had echo.
        assert_eq!(console_mode_without_echo(suppressed), suppressed);
        assert_eq!(console_mode_without_echo(0), 0);
    }

    /// Engaging against a non-console stdin must answer `None` quietly.
    ///
    /// This is the branch a GitHub-hosted Windows runner actually takes —
    /// the test process is handed a pipe, so `GetConsoleMode` fails — and
    /// it is the branch that must not panic, must not corrupt the handle,
    /// and must leave the caller reading exactly as it did before. It
    /// runs on Unix too, where a non-tty stdin is the same story.
    #[test]
    fn engage_is_harmless_when_stdin_is_not_a_terminal() {
        use std::io::IsTerminal as _;
        if std::io::stdin().is_terminal() {
            // Someone is running the suite from a terminal with stdin
            // attached; this test has nothing to say about that case.
            return;
        }
        let guard = EchoOff::engage();
        assert!(
            guard.is_none(),
            "engaged echo suppression on a stdin that is not a terminal"
        );
        drop(guard);
    }
}
