//! Foreign capability lifetime and encrypted host-metadata publication.

use hidden_volume_ffi::{ArgonPreset, PreparedCompactionHandle, SpaceHandle, WriteOp};

fn fixture() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.hv").to_str().unwrap().to_owned();
    let child =
        SpaceHandle::create(path.clone(), b"child".to_vec(), ArgonPreset::Min, 0, 1).unwrap();
    let keys = child.space_keys().unwrap();
    child
        .commit(vec![put(b"body", b"retained child payload")])
        .unwrap();
    drop(child);
    let master = SpaceHandle::add_space(path.clone(), b"master".to_vec()).unwrap();
    master.commit(vec![put(b"child", &keys)]).unwrap();
    drop(master);
    (dir, path)
}

fn put(key: &[u8], value: &[u8]) -> WriteOp {
    WriteOp::Put {
        namespace: 1,
        key: key.to_vec(),
        value: value.to_vec(),
    }
}

fn verify(path: &str) -> Vec<u8> {
    let master = SpaceHandle::open(path.to_owned(), b"master".to_vec()).unwrap();
    let keys = master.get(1, b"child".to_vec()).unwrap().unwrap();
    drop(master);
    let child = SpaceHandle::open_with_keys(path.to_owned(), keys.clone()).unwrap();
    assert_eq!(
        child.get(1, b"body".to_vec()).unwrap().as_deref(),
        Some(b"retained child payload".as_slice())
    );
    keys
}

fn prepare(plan: &PreparedCompactionHandle, path: &str) -> String {
    plan.prepare(path.to_owned(), vec![b"child".to_vec(), b"master".to_vec()])
        .unwrap()
}

#[test]
fn borrowed_worker_reference_repairs_before_publication() {
    let (_dir, path) = fixture();
    let old_keys = verify(&path);
    let before = std::fs::read(&path).unwrap();
    let owner = PreparedCompactionHandle::new();
    let worker = owner.clone();
    let staged = prepare(&worker, &path);
    drop(worker); // A worker reply is not ownership of the underlying plan.
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let child = SpaceHandle::open(staged.clone(), b"child".to_vec()).unwrap();
    let keys = child.space_keys().unwrap();
    drop(child);
    assert_ne!(keys, old_keys);
    let master = SpaceHandle::open(staged, b"master".to_vec()).unwrap();
    master.commit(vec![put(b"child", &keys)]).unwrap();
    drop(master);
    owner.commit().unwrap();
    owner.abort().unwrap(); // Idempotent drain after commit does not undo it.
    assert_eq!(verify(&path), keys);
    assert!(owner.commit().is_err());
    assert!(owner.prepare(path, vec![b"master".to_vec()]).is_err());
}

#[test]
fn lost_prepare_reply_can_be_aborted_by_original_owner() {
    let (dir, path) = fixture();
    let before = std::fs::read(&path).unwrap();
    let owner = PreparedCompactionHandle::new();
    let worker = owner.clone();
    let source = path.clone();
    std::thread::spawn(move || {
        let _lost = prepare(&worker, &source);
    })
    .join()
    .unwrap();
    owner.abort().unwrap();
    owner.abort().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    verify(&path);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn abort_before_dispatch_denies_late_worker() {
    let (_dir, path) = fixture();
    let before = std::fs::read(&path).unwrap();
    let owner = PreparedCompactionHandle::new();
    let worker = owner.clone();
    owner.abort().unwrap();
    assert!(
        worker
            .prepare(path.clone(), vec![b"child".to_vec()])
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    verify(&path);
}

#[test]
fn failed_prepare_releases_source_and_is_terminal() {
    let (_dir, path) = fixture();
    let before = std::fs::read(&path).unwrap();
    let owner = PreparedCompactionHandle::new();
    assert!(
        owner
            .prepare(path.clone(), vec![b"wrong".to_vec()])
            .is_err()
    );
    owner.abort().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    verify(&path);
    assert!(owner.prepare(path, vec![b"master".to_vec()]).is_err());
}
