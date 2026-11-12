//! Repair encrypted key references while the original is still recoverable.

use std::path::{Path, PathBuf};

use hidden_volume::cancel::CancelToken;
use hidden_volume::container::{PreparedCompaction, RepackOptions};
use hidden_volume::crypto::derive::SpaceKeys;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::space::index::Namespace;
use hidden_volume::{Container, Error};

// A subprocess can briefly inherit another thread's close-on-exec file
// descriptors before exec, retaining their flock after that thread closes it.
// Keep process-launch/crash cases exclusive; ordinary fixtures still run in
// parallel under shared guards. This is test isolation, not a storage retry.
static PROCESS_LAUNCH: std::sync::RwLock<()> = std::sync::RwLock::new(());

const PASSWORDS: &[&[u8]] = &[b"child-fixture", b"master-fixture"];
const BODY: &[u8] = b"actual child payload retained across publication";

fn encode(keys: &SpaceKeys) -> Vec<u8> {
    [keys.container_id.as_slice(), keys.aead_root.as_slice()].concat()
}

fn decode(bytes: &[u8]) -> SpaceKeys {
    assert_eq!(bytes.len(), 64);
    SpaceKeys {
        container_id: bytes[..32].try_into().unwrap(),
        aead_root: bytes[32..].try_into().unwrap(),
    }
}

fn fixture() -> (tempfile::TempDir, PathBuf, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.hv");
    {
        let mut container = Container::create(&path, Argon2Params::MIN).unwrap();
        let keys = {
            let mut child = container.create_space(PASSWORDS[0]).unwrap();
            let keys = child.space_keys();
            let mut tx = child.begin_tx();
            tx.put(Namespace::SETTINGS, b"body", BODY).unwrap();
            tx.commit().unwrap();
            encode(&keys)
        };
        let mut master = container.create_space(PASSWORDS[1]).unwrap();
        let mut tx = master.begin_tx();
        tx.put(Namespace::SETTINGS, b"child-reference", &keys)
            .unwrap();
        tx.commit().unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    (dir, path, before)
}

fn verify_master(path: &Path) -> Vec<u8> {
    let mut container = Container::open(path).unwrap();
    let reference = container
        .open_space(PASSWORDS[1])
        .unwrap()
        .get(Namespace::SETTINGS, b"child-reference")
        .unwrap()
        .unwrap();
    let mut child = container.open_space_with_keys(decode(&reference)).unwrap();
    assert_eq!(
        child.get(Namespace::SETTINGS, b"body").unwrap().as_deref(),
        Some(BODY)
    );
    reference
}

fn repair(plan: &PreparedCompaction) {
    let mut staged = Container::open(plan.staged_path()).unwrap();
    let keys = staged.open_space(PASSWORDS[0]).unwrap().space_keys();
    let mut master = staged.open_space(PASSWORDS[1]).unwrap();
    let mut tx = master.begin_tx();
    tx.put(Namespace::SETTINGS, b"child-reference", &encode(&keys))
        .unwrap();
    tx.commit().unwrap();
}

#[test]
fn publish_contains_repaired_references_and_still_rotates_keys() {
    let _launch_gate = PROCESS_LAUNCH.read().unwrap();
    let (dir, path, _) = fixture();
    let old = verify_master(&path);
    let before = std::fs::read(&path).unwrap();
    let plan =
        Container::prepare_compact_known(&path, PASSWORDS, RepackOptions::default()).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(matches!(Container::open(&path), Err(Error::Busy)));
    assert_eq!(plan.staged_path().parent(), path.parent());
    assert!(!format!("{plan:?}").contains(&path.parent().unwrap().display().to_string()));
    repair(&plan);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    plan.commit().unwrap();
    let current = verify_master(&path);
    assert_ne!(old, current);
    let mut container = Container::open(&path).unwrap();
    assert!(matches!(
        container.open_space_with_keys(decode(&old)),
        Err(Error::AuthFailed)
    ));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn abort_after_staged_metadata_edits_preserves_original_bytes() {
    let _launch_gate = PROCESS_LAUNCH.read().unwrap();
    let (dir, path, before) = fixture();
    let plan =
        Container::prepare_compact_known(&path, PASSWORDS, RepackOptions::default()).unwrap();
    repair(&plan);
    plan.abort().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    verify_master(&path);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn invalid_password_never_exposes_a_partial_replacement() {
    let _launch_gate = PROCESS_LAUNCH.read().unwrap();
    let (dir, path, before) = fixture();
    match Container::prepare_compact_known(&path, &[b"wrong-fixture"], RepackOptions::default()) {
        Err(Error::AuthFailed) => {},
        Err(other) => panic!("unexpected failure kind: {}", other.variant_name()),
        Ok(plan) => {
            plan.abort().unwrap();
            panic!("wrong password prepared a replacement");
        },
    }
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn cancellation_before_publish_keeps_original_references() {
    let _launch_gate = PROCESS_LAUNCH.read().unwrap();
    let (dir, path, before) = fixture();
    let token = CancelToken::new();
    let plan = Container::prepare_compact_known_cancellable(
        &path,
        PASSWORDS,
        RepackOptions::default(),
        &token,
    )
    .unwrap();
    repair(&plan);
    token.cancel();
    assert!(matches!(plan.commit(), Err(Error::Cancelled)));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    verify_master(&path);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn open_staged_handle_refuses_publication() {
    let _launch_gate = PROCESS_LAUNCH.read().unwrap();
    let (_dir, path, before) = fixture();
    let plan =
        Container::prepare_compact_known(&path, PASSWORDS, RepackOptions::default()).unwrap();
    let open = Container::open(plan.staged_path()).unwrap();
    let result = plan.commit();
    assert!(matches!(
        result,
        Err(Error::Busy) | Err(Error::RewriteCleanupFailed { .. })
    ));
    drop(open);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    verify_master(&path);
}

#[test]
fn invalid_staged_header_does_not_replace_source() {
    let _launch_gate = PROCESS_LAUNCH.read().unwrap();
    let (_dir, path, before) = fixture();
    let plan =
        Container::prepare_compact_known(&path, PASSWORDS, RepackOptions::default()).unwrap();
    std::fs::write(plan.staged_path(), [0u8; 48]).unwrap();
    assert!(plan.commit().is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    verify_master(&path);
}

#[test]
fn already_cancelled_preparation_never_changes_source() {
    let _launch_gate = PROCESS_LAUNCH.read().unwrap();
    let (dir, path, before) = fixture();
    let token = CancelToken::new();
    token.cancel();
    assert!(matches!(
        Container::prepare_compact_known_cancellable(
            &path,
            PASSWORDS,
            RepackOptions::default(),
            &token,
        ),
        Err(Error::Cancelled)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn qualified_alias_warning_still_publishes_repaired_references() {
    let _launch_gate = PROCESS_LAUNCH.read().unwrap();
    let (dir, path, before) = fixture();
    let alias = dir.path().join("alias.hv");
    std::fs::hard_link(&path, &alias).unwrap();
    let plan =
        Container::prepare_compact_known(&path, PASSWORDS, RepackOptions::default()).unwrap();
    repair(&plan);
    assert!(matches!(
        plan.commit(),
        Err(Error::RenameVisibleAliasesNotRevoked(..)
            | Error::RenameVisibleAliasesUnknown
            | Error::RenameVisibleAliasesAndDurabilityUncertain { .. })
    ));
    assert_eq!(std::fs::read(&alias).unwrap(), before);
    let current = verify_master(&path);
    let old = verify_master(&alias);
    assert_ne!(current, old);
}

fn crash_case(test_name: &str, publish: bool) {
    use std::io::BufRead;
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    const FIXTURE_PATH: &str = "_HV_PREPARED_KILL_FIXTURE";
    const READY: &str = "HV_PREPARED_FIXTURE_READY";
    if let Some(path) = std::env::var_os(FIXTURE_PATH) {
        let plan =
            Container::prepare_compact_known(Path::new(&path), PASSWORDS, RepackOptions::default())
                .unwrap();
        repair(&plan);
        if publish {
            plan.commit().unwrap();
        }
        println!("{READY}");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        loop {
            std::thread::park();
        }
    }

    struct Actor(Option<Child>);
    impl Drop for Actor {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let _launch_gate = PROCESS_LAUNCH.write().unwrap();
    let (_dir, path, _) = fixture();
    let old = verify_master(&path);
    let before = std::fs::read(&path).unwrap();
    let mut actor = Actor(Some(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(FIXTURE_PATH, &path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    let stdout = actor.0.as_mut().unwrap().stdout.take().unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            if line.is_ok_and(|text| text.contains(READY)) {
                let _ = ready_tx.send(());
                return;
            }
        }
    });
    // A watchdog for a broken fixture, not a performance assertion.
    let ready = ready_rx.recv_timeout(Duration::from_secs(20));
    let source_still_locked = publish || matches!(Container::open(&path), Err(Error::Busy));
    let prepared_file_count = std::fs::read_dir(path.parent().unwrap()).unwrap().count();
    let child = actor.0.as_mut().unwrap();
    let killed = child.kill();
    let status = child.wait();
    if status.is_ok() {
        actor.0.take();
    }
    reader.join().unwrap();
    assert!(
        ready.is_ok(),
        "fixture did not reach its publication boundary"
    );
    assert!(
        source_still_locked,
        "fixture released its source before commit"
    );
    assert_eq!(prepared_file_count, if publish { 1 } else { 2 });
    killed.unwrap();
    let status = status.unwrap();
    assert!(!status.success());
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
    }
    if !publish {
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    let actual = verify_master(&path);
    assert_eq!(actual == old, !publish);
}

#[test]
fn process_kill_before_publication_keeps_original_master() {
    crash_case(
        "process_kill_before_publication_keeps_original_master",
        false,
    );
}

#[test]
fn process_kill_after_publication_keeps_repaired_master() {
    crash_case("process_kill_after_publication_keeps_repaired_master", true);
}
