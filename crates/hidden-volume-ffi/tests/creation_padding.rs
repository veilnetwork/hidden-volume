//! Explicit creation posture survives cold open and native compaction.
use hidden_volume::Container;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume_ffi::{
    ArgonPreset, PaddingPreset, PreparedCompactionHandle, SpaceHandle, WriteOp,
};

fn policy(path: &str) -> PaddingPolicy {
    Container::open(std::path::Path::new(path))
        .unwrap()
        .padding_policy()
}

#[test]
fn explicit_creation_persists_each_policy_and_legacy_default_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    for (index, (preset, expected)) in [
        (PaddingPreset::None, PaddingPolicy::None),
        (
            PaddingPreset::Bucket256Kib,
            PaddingPolicy::BucketGrowth { bucket_chunks: 64 },
        ),
        (
            PaddingPreset::Bucket1Mib,
            PaddingPolicy::BucketGrowth { bucket_chunks: 256 },
        ),
        (
            PaddingPreset::Bucket16Mib,
            PaddingPolicy::BucketGrowth {
                bucket_chunks: 4096,
            },
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let path = dir
            .path()
            .join(format!("explicit-{index}.hv"))
            .to_str()
            .unwrap()
            .to_owned();
        let space = SpaceHandle::create_with_padding(
            path.clone(),
            b"fixture".to_vec(),
            ArgonPreset::Min,
            0,
            1,
            preset,
        )
        .unwrap();
        drop(space);
        assert_eq!(policy(&path), expected);
    }
    let path = dir.path().join("legacy.hv").to_str().unwrap().to_owned();
    let space =
        SpaceHandle::create(path.clone(), b"fixture".to_vec(), ArgonPreset::Min, 0, 1).unwrap();
    drop(space);
    assert_eq!(policy(&path), PaddingPolicy::DEFAULT);
}

#[test]
fn prepared_compaction_preserves_explicit_no_padding_and_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("managed.hv").to_str().unwrap().to_owned();
    let space = SpaceHandle::create_with_padding(
        path.clone(),
        b"fixture".to_vec(),
        ArgonPreset::Min,
        0,
        1,
        PaddingPreset::None,
    )
    .unwrap();
    space
        .commit(vec![WriteOp::Put {
            namespace: 1,
            key: b"key".to_vec(),
            value: b"value".to_vec(),
        }])
        .unwrap();
    drop(space);
    let plan = PreparedCompactionHandle::new();
    let staged = plan
        .prepare(path.clone(), vec![b"fixture".to_vec()])
        .unwrap();
    assert_eq!(policy(&staged), PaddingPolicy::None);
    plan.commit().unwrap();
    assert_eq!(policy(&path), PaddingPolicy::None);
    let reopened = SpaceHandle::open(path, b"fixture".to_vec()).unwrap();
    assert_eq!(
        reopened.get(1, b"key".to_vec()).unwrap(),
        Some(b"value".to_vec())
    );
}
