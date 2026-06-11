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
//! incompatible with the compelled-key deniability story.

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
fn read_password(prompt: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line).map_err(|e| {
        hidden_volume::Error::Io(std::io::Error::other(format!(
            "read password from stdin: {e}"
        )))
    })?;
    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }
    Ok(zeroize::Zeroizing::new(line.into_bytes()))
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
    let mut c = Container::open(&path)?;
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
    // `RepackOptions::default()` already uses `Argon2Params::DEFAULT`
    // for the destination. Audit F5 (2026-05-03) — drop the redundant
    // explicit field.
    Container::repack(&source, &dest, &pw_refs, RepackOptions::default())?;
    println!("repacked: {} → {}", source.display(), dest.display());
    Ok(())
}
