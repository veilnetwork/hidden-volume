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
//! When stdin is a **terminal**, echo is suppressed while the password
//! is typed (report6 P2) — on Unix; see `EchoOff`. A piped or
//! redirected password takes exactly the path it always did.

use std::io::{BufRead, Write};
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
    let mut line = String::new();
    let read = stdin.lock().read_line(&mut line);
    // Restore the terminal BEFORE anything can return early, so a read
    // error does not leave the user's shell with echo off.
    drop(echo_off);
    read.map_err(|e| {
        hidden_volume::Error::Io(std::io::Error::other(format!(
            "read password from stdin: {e}"
        )))
    })?;
    if interactive {
        // The Enter that ended the line was not echoed either, so
        // without this the next thing written lands on the prompt's
        // own line.
        eprintln!();
    }
    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }
    Ok(zeroize::Zeroizing::new(line.into_bytes()))
}

/// Terminal echo, off for as long as this value lives.
///
/// A guard rather than a pair of calls so that every early return
/// between engage and drop — a read error, a panic — still restores the
/// caller's terminal. Leaving a shell with `ECHO` cleared is a bad way
/// to fail.
///
/// **Unix only.** `IsTerminal` answers on every platform, but turning
/// echo off does not: Windows needs `SetConsoleMode`, and this host
/// cannot compile, let alone run, that branch, so shipping it would
/// mean shipping code nobody has executed. On Windows `engage` answers
/// `None` and the read behaves as it did before — stated here rather
/// than papered over.
///
/// Not signal-safe: a SIGINT between engage and drop leaves the
/// terminal with echo off until `stty sane`. That is the same hole
/// `getpass(3)` and every password prompt built on `tcsetattr` has, and
/// closing it means installing a handler this binary has no other
/// reason to own.
struct EchoOff {
    #[cfg(unix)]
    saved: libc::termios,
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

    #[cfg(not(unix))]
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
    }
}

fn read_all_passwords() -> Result<Vec<zeroize::Zeroizing<Vec<u8>>>> {
    let stdin = std::io::stdin();
    let mut out: Vec<zeroize::Zeroizing<Vec<u8>>> = Vec::new();
    for line in stdin.lock().lines() {
        let mut s = line.map_err(|e| {
            hidden_volume::Error::Io(std::io::Error::other(format!(
                "read password from stdin: {e}"
            )))
        })?;
        if s.ends_with('\r') {
            s.pop();
        }
        if !s.is_empty() {
            out.push(zeroize::Zeroizing::new(s.into_bytes()));
        }
    }
    Ok(out)
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
        let stdin = std::io::stdin();
        let mut line = String::new();
        stdin.lock().read_line(&mut line).map_err(|e| {
            hidden_volume::Error::Io(std::io::Error::other(format!("read value from stdin: {e}")))
        })?;
        if line.ends_with('\n') {
            line.pop();
        }
        if line.ends_with('\r') {
            line.pop();
        }
        line.into_bytes()
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
