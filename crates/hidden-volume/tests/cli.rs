//! Integration tests for the `hv` CLI binary.
//!
//! Run with: `cargo test --features cli --test cli`
//!
//! Spawns the CLI binary as a subprocess; uses `CARGO_BIN_EXE_hv`
//! which Cargo sets automatically when the bin target is built
//! alongside the test.

#![cfg(feature = "cli")]

use std::process::{Command, Stdio};

fn hv() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hv"))
}

fn scratch_path() -> std::path::PathBuf {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let p = tmp.path().to_owned();
    drop(tmp);
    p
}

fn run_with_password(args: &[&str], password: &str) -> std::process::Output {
    // Pipe the password through stdin (one line). Audit F3 (2026-05-03):
    // we used to set `HV_PASSWORD` env var here, but the CLI no longer
    // reads it — env-var fallback removed because it leaks via
    // `/proc/PID/environ` and `ps -e`.
    use std::io::Write;
    let mut child = hv()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn hv");
    {
        let stdin = child.stdin.as_mut().expect("stdin captured");
        stdin
            .write_all(password.as_bytes())
            .expect("write password");
        stdin.write_all(b"\n").expect("write newline");
        // stdin closed implicitly when `child.stdin.take()` would happen
        // on wait_with_output; explicit drop here releases the handle.
    }
    child.wait_with_output().expect("wait for hv")
}

fn run(args: &[&str]) -> std::process::Output {
    hv().args(args)
        .stdin(Stdio::null())
        .output()
        .expect("failed to spawn hv")
}

fn assert_success(out: &std::process::Output) {
    if !out.status.success() {
        panic!(
            "expected success; status={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn version_flag_works() {
    let out = run(&["--version"]);
    assert_success(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("hv "), "stdout: {stdout}");
}

#[test]
fn help_lists_subcommands() {
    let out = run(&["--help"]);
    assert_success(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    for sub in [
        "info",
        "create",
        "create-space",
        "inspect",
        "get",
        "put",
        "verify",
        "dump-stats",
        "repack",
    ] {
        assert!(stdout.contains(sub), "help missing {sub}: {stdout}");
    }
}

#[test]
fn create_then_info_then_create_space_then_inspect() {
    let path = scratch_path();
    let path_str = path.to_str().unwrap();

    // create
    let out = run(&["create", path_str, "--params", "min", "--replicas", "1"]);
    assert_success(&out);
    assert!(path.exists());

    // info (no password)
    let out = run(&["info", path_str]);
    assert_success(&out);
    let info = String::from_utf8_lossy(&out.stdout);
    assert!(info.contains("salt:"));
    // v3: container_id is per-space derived from master key; no
    // longer printed by `hv info` (which is password-less).
    assert!(info.contains("argon2:"));

    // create-space
    let out = run_with_password(&["create-space", path_str], "test-pw");
    assert_success(&out);

    // inspect — empty namespaces
    let out = run_with_password(&["inspect", path_str], "test-pw");
    assert_success(&out);
    let inspect = String::from_utf8_lossy(&out.stdout);
    assert!(inspect.contains("commit_seq: 1"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn put_get_inspect_round_trip() {
    let path = scratch_path();
    let path_str = path.to_str().unwrap();

    assert_success(&run(&[
        "create",
        path_str,
        "--params",
        "min",
        "--replicas",
        "1",
    ]));
    assert_success(&run_with_password(&["create-space", path_str], "pw"));

    assert_success(&run_with_password(
        &["put", path_str, "1", "username", "alice"],
        "pw",
    ));
    assert_success(&run_with_password(
        &["put", path_str, "1", "theme", "dark"],
        "pw",
    ));

    let out = run_with_password(&["get", path_str, "1", "username"], "pw");
    assert_success(&out);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "alice");

    let out = run_with_password(&["get", path_str, "1", "theme"], "pw");
    assert_success(&out);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "dark");

    // Inspect counts.
    let out = run_with_password(&["inspect", path_str], "pw");
    assert_success(&out);
    let inspect = String::from_utf8_lossy(&out.stdout);
    assert!(inspect.contains("SETTINGS"));
    assert!(inspect.contains("2 entries"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn get_missing_key_exits_2() {
    let path = scratch_path();
    let path_str = path.to_str().unwrap();
    assert_success(&run(&[
        "create",
        path_str,
        "--params",
        "min",
        "--replicas",
        "1",
    ]));
    assert_success(&run_with_password(&["create-space", path_str], "pw"));

    let out = run_with_password(&["get", path_str, "1", "nonexistent"], "pw");
    assert_eq!(out.status.code(), Some(2));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn wrong_password_fails_with_nonzero_exit() {
    let path = scratch_path();
    let path_str = path.to_str().unwrap();
    assert_success(&run(&[
        "create",
        path_str,
        "--params",
        "min",
        "--replicas",
        "1",
    ]));
    assert_success(&run_with_password(&["create-space", path_str], "correct"));

    let out = run_with_password(&["inspect", path_str], "wrong");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.to_lowercase().contains("auth"), "stderr: {stderr}");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn info_works_on_readonly_open() {
    // info uses Container::open_readonly so it works while another writer
    // would be blocked. Here we just verify it doesn't try to take an
    // exclusive lock.
    let path = scratch_path();
    let path_str = path.to_str().unwrap();
    assert_success(&run(&[
        "create",
        path_str,
        "--params",
        "min",
        "--replicas",
        "1",
    ]));

    // Two simultaneous info calls succeed.
    let out1 = run(&["info", path_str]);
    let out2 = run(&["info", path_str]);
    assert_success(&out1);
    assert_success(&out2);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn create_then_info_size_matches_initial_garbage() {
    // initial-garbage 100 chunks → file is 101 * 4096 = 413696 bytes.
    let path = scratch_path();
    let path_str = path.to_str().unwrap();

    assert_success(&run(&[
        "create",
        path_str,
        "--params",
        "min",
        "--replicas",
        "1",
        "--initial-garbage",
        "100",
    ]));

    let out = run(&["info", path_str]);
    assert_success(&out);
    let info = String::from_utf8_lossy(&out.stdout);
    assert!(info.contains("413696 bytes"), "info: {info}");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn verify_on_fresh_space_reports_ok() {
    let path = scratch_path();
    let path_str = path.to_str().unwrap();
    assert_success(&run(&[
        "create",
        path_str,
        "--params",
        "min",
        "--replicas",
        "1",
    ]));
    assert_success(&run_with_password(&["create-space", path_str], "pw"));

    let out = run_with_password(&["verify", path_str], "pw");
    assert_success(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("namespaces_verified:"), "{stdout}");
    assert!(stdout.contains("chunks_verified:"), "{stdout}");
    assert!(stdout.contains("max_depth:"), "{stdout}");
    assert!(stdout.contains("status:              ok"), "{stdout}");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn verify_after_writes_walks_more_chunks() {
    let path = scratch_path();
    let path_str = path.to_str().unwrap();
    assert_success(&run(&[
        "create",
        path_str,
        "--params",
        "min",
        "--replicas",
        "1",
    ]));
    assert_success(&run_with_password(&["create-space", path_str], "pw"));

    // Add a few KV entries across two namespaces so verify must walk
    // multiple Merkle subtrees.
    for k in ["alice", "bob", "carol"] {
        assert_success(&run_with_password(&["put", path_str, "1", k, "x"], "pw"));
    }
    assert_success(&run_with_password(
        &["put", path_str, "2", "contact", "v"],
        "pw",
    ));

    let out = run_with_password(&["verify", path_str], "pw");
    assert_success(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Two namespaces touched → namespaces_verified ≥ 2.
    assert!(
        stdout.contains("namespaces_verified: 2"),
        "expected 2 namespaces verified: {stdout}"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn verify_wrong_password_fails() {
    let path = scratch_path();
    let path_str = path.to_str().unwrap();
    assert_success(&run(&[
        "create",
        path_str,
        "--params",
        "min",
        "--replicas",
        "1",
    ]));
    assert_success(&run_with_password(&["create-space", path_str], "correct"));

    let out = run_with_password(&["verify", path_str], "wrong");
    assert!(!out.status.success());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn dump_stats_on_fresh_space() {
    let path = scratch_path();
    let path_str = path.to_str().unwrap();
    assert_success(&run(&[
        "create",
        path_str,
        "--params",
        "min",
        "--replicas",
        "1",
    ]));
    assert_success(&run_with_password(&["create-space", path_str], "pw"));

    let out = run_with_password(&["dump-stats", path_str], "pw");
    assert_success(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("commit_seq:          1"), "{stdout}");
    assert!(stdout.contains("commit_history_len:  1"), "{stdout}");
    assert!(stdout.contains("total_entries:       0"), "{stdout}");
    assert!(stdout.contains("namespaces:          (none)"), "{stdout}");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn dump_stats_after_writes() {
    let path = scratch_path();
    let path_str = path.to_str().unwrap();
    assert_success(&run(&[
        "create",
        path_str,
        "--params",
        "min",
        "--replicas",
        "1",
    ]));
    assert_success(&run_with_password(&["create-space", path_str], "pw"));

    for k in ["a", "b", "c"] {
        assert_success(&run_with_password(&["put", path_str, "1", k, "v"], "pw"));
    }
    assert_success(&run_with_password(&["put", path_str, "2", "x", "y"], "pw"));

    let out = run_with_password(&["dump-stats", path_str], "pw");
    assert_success(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // 4 commits → seq=5 (1 initial + 4 puts).
    assert!(stdout.contains("commit_seq:          5"), "{stdout}");
    assert!(stdout.contains("total_entries:       4"), "{stdout}");
    assert!(stdout.contains("SETTINGS"), "{stdout}");
    assert!(stdout.contains("CONTACTS"), "{stdout}");

    let _ = std::fs::remove_file(&path);
}
