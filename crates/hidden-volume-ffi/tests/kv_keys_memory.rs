//! `SpaceHandle::kv_keys` must not materialise the namespace's values
//! (report5 HV-04).
//!
//! The call went through `Space::list`, which builds a
//! `Vec<(Vec<u8>, Vec<u8>)>` of the WHOLE namespace, and then dropped
//! every value while framing the keys. Its rustdoc meanwhile promised
//! "the same O(N) index walk as `count`" with "values not decoded" —
//! `count` peaks at one decoded node. On a namespace of message bodies
//! that is the difference between holding the keys and holding the
//! entire plaintext, on the device class this library exists for.
//!
//! ## Why this test measures allocation
//!
//! Every assertion about *which keys come back* passes just as happily
//! against the `list`-based implementation — the defect was never
//! visible in the return value. So a keys-are-correct test cannot catch
//! a regression here, and this file's job is to be the one that can.
//! A counting global allocator is the only way to see the property from
//! inside the process.
//!
//! **This file must hold exactly one `#[test]`.** `PEAK`/`LIVE` are
//! process-global and `cargo test` runs a binary's tests on parallel
//! threads, so a second test here would measure the first one's
//! allocations. Cargo gives every `tests/*.rs` its own binary, so the
//! tracking allocator does not reach the rest of the suite.

use hidden_volume_ffi::{ArgonPreset, SpaceHandle, WriteOp};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// Pass-through allocator that tracks live bytes and their high-water
/// mark. `realloc` / `alloc_zeroed` are left at their default
/// implementations, which route through `alloc` + `dealloc` here.
struct Tracking;

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Tracking = Tracking;

/// Run `f` and return how far live heap bytes rose above where they
/// started.
fn peak_growth<T>(f: impl FnOnce() -> T) -> (usize, T) {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let value = f();
    let peak = PEAK.load(Ordering::Relaxed);
    (peak.saturating_sub(before), value)
}

const NAMESPACE: u8 = 1;
const ENTRIES: usize = 1500;
/// `MAX_VALUE_LEN`. Paired with 8-byte keys this makes values 256× the
/// key bytes, so the two costs cannot be confused for one another.
const VALUE_LEN: usize = 2048;

#[test]
fn kv_keys_does_not_materialise_values() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let handle = SpaceHandle::create(
        path.to_string_lossy().into_owned(),
        b"pw".to_vec(),
        ArgonPreset::Min,
        0,
        1,
    )
    .unwrap();

    let ops: Vec<WriteOp> = (0..ENTRIES)
        .map(|i| WriteOp::Put {
            namespace: NAMESPACE,
            key: (i as u64).to_be_bytes().to_vec(),
            value: vec![0xAB; VALUE_LEN],
        })
        .collect();
    handle.commit(ops).unwrap();

    let key_bytes = ENTRIES * 8;
    let value_bytes = ENTRIES * VALUE_LEN;

    // Warm any lazily-populated state first, so what the measurements
    // below see is the walk's own allocation and not a one-off cache
    // fill attributed to whichever call happened to run first.
    let _ = handle.kv_keys(NAMESPACE).unwrap();

    let (peak, framed) = peak_growth(|| handle.kv_keys(NAMESPACE).unwrap());

    // Sanity: we really did enumerate the whole namespace. Without this
    // the bound below would also be satisfied by returning nothing.
    assert_eq!(
        u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize,
        ENTRIES,
        "kv_keys did not return every key"
    );

    // The budget is per-KEY bookkeeping, and it is not zero: live at the
    // moment of the peak are the `Vec<Vec<u8>>` spine (24 B per key),
    // each key's own allocation, the `4 + ENTRIES * (4 + len)` framed
    // buffer, and — because the default `realloc` allocates the new
    // block before freeing the old — one spine growth step's worth of
    // both. That accounting comes to ~96 B per entry; the slack covers
    // one decoded node and the harness. Measured: ~107 KB at
    // ENTRIES = 1500.
    let budget = ENTRIES * 96 + 64 * 1024;
    assert!(
        peak < budget,
        "kv_keys peaked at {peak} bytes for {ENTRIES} keys / {key_bytes} \
         bytes of key data (budget {budget}) — it is holding more than \
         the keys"
    );
    // The finding itself: the peak must not scale with the VALUES.
    assert!(
        peak < value_bytes / 8,
        "kv_keys peaked at {peak} bytes against {value_bytes} bytes of \
         values — the values are being materialised"
    );

    // And the calibration that keeps the two bounds above honest: the
    // pair-materialising walk is still in the tree (`Space::list` backs
    // repack and the commit flatten), so we can show on this very
    // container that the numbers above are a property of the new walk
    // and not of a namespace that was too small to tell the difference.
    //
    // The handle holds the file's exclusive flock, so it has to go
    // before the container can be reopened.
    drop(framed);
    drop(handle);
    let (list_peak, _) = peak_growth(|| {
        let mut container = hidden_volume::Container::open(&path).unwrap();
        let mut space = container.open_space(b"pw").unwrap();
        space
            .list(hidden_volume::space::index::Namespace(NAMESPACE))
            .unwrap()
    });
    assert!(
        list_peak > value_bytes / 2,
        "calibration failed: `Space::list` peaked at {list_peak} bytes on \
         {value_bytes} bytes of values, so this container is too small to \
         distinguish the two walks and the assertions above prove nothing"
    );

    let _ = std::fs::remove_file(&path);
}
