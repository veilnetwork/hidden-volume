//! The constant-time scan's timing equalizer must not allocate a fresh
//! buffer per rejected chunk (audit HV-12).
//!
//! `equalize_timing_via_chacha20` ran `vec![0u8; body_len]` on every
//! chunk whose tag did not verify, and its one call site passes the
//! compile-time constant `PLAINTEXT_LEN`. So the size never varied and
//! the buffer was thrown away immediately: one ~4 KiB allocate/free per
//! foreign chunk, on the path the FFI takes by default. At the format's
//! 16 M-chunk ceiling that is on the order of 65 GB of allocator
//! traffic for a single unlock.
//!
//! ## This is a cost, not a leak
//!
//! The audit filed it as a side channel. It is not: `body_len` is a
//! constant at the only call site, so the allocation's size — and
//! therefore its cost — carries nothing about the chunk, the key, or
//! whether the tag matched. If anything the reusable buffer is the
//! better of the two for the property the equalizer exists to protect,
//! since it also removes the equalizer's dependence on allocator state,
//! which is the one part of that cost nobody controls.
//!
//! ## How this measures it
//!
//! By allocation SIZE: how many allocations of exactly `PLAINTEXT_LEN`
//! bytes one constant-time open makes.
//!
//! Two other approaches were tried and rejected. A peak-heap watermark
//! cannot see it — the buffer is freed before the next chunk is read,
//! so only one is ever live. And total bytes across a constant-time
//! open minus the same across a plain open, which looks like the
//! natural way to isolate the one flag that differs, measured **zero**
//! on a 4005-chunk container while the equalizer was demonstrably
//! running (multiplying its buffer tenfold moved the number by exactly
//! nine buffers per chunk). The plain open attempts the checkpoint fast
//! scan first, and that attempt reads its way through the file for
//! almost precisely the bytes the equalizer costs, so the subtraction
//! cancelled the very term it was meant to expose.
//!
//! Sizes are what tell the per-chunk allocations apart here: the
//! equalizer's buffer is `PLAINTEXT_LEN`, the AEAD's own per-attempt
//! buffer is `CHUNK_SIZE - NONCE_LEN`, and a slot read is `CHUNK_SIZE`.
//! All three differ.
//!
//! **This file must hold exactly one `#[test]`.** The counters are
//! process-global and `cargo test` runs a binary's tests in parallel.

use hidden_volume::Container;
use hidden_volume::container::ContainerOptions;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::padding::PaddingPolicy;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// The equalizer's discarded buffer.
const EQUALIZER_SIZE: usize = hidden_volume::PLAINTEXT_LEN;
/// The buffer `chacha20poly1305`'s `decrypt` builds for each trial —
/// ciphertext plus tag, i.e. a chunk minus its nonce. Counted as the
/// calibration: a per-chunk allocation that is NOT under test and must
/// still be there, so seeing it proves both that the instrument works
/// and that the scan really did try every chunk.
const AEAD_TRIAL_SIZE: usize = hidden_volume::CHUNK_SIZE - hidden_volume::NONCE_LEN;

static COUNTING: AtomicBool = AtomicBool::new(false);
static EQUALIZER_ALLOCS: AtomicUsize = AtomicUsize::new(0);
static AEAD_ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() && COUNTING.load(Ordering::Relaxed) {
            match layout.size() {
                EQUALIZER_SIZE => {
                    EQUALIZER_ALLOCS.fetch_add(1, Ordering::Relaxed);
                },
                AEAD_TRIAL_SIZE => {
                    AEAD_ALLOCS.fetch_add(1, Ordering::Relaxed);
                },
                _ => {},
            }
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Garbage chunks in the fixture. Every one of them fails its tag
/// check, so every one of them reaches the equalizer.
const GARBAGE_CHUNKS: u64 = 4000;

fn scratch() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "hv12-{}-{:?}.bin",
        std::process::id(),
        std::thread::current().id()
    ))
}

struct Cleanup(std::path::PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn the_timing_equalizer_does_not_allocate_per_rejected_chunk() {
    // Two distinct sizes, or the two counters are one counter.
    assert_ne!(EQUALIZER_SIZE, AEAD_TRIAL_SIZE);

    let path = scratch();
    let _cleanup = Cleanup(path.clone());
    let _ = std::fs::remove_file(&path);

    {
        let mut c = Container::create_with_options(
            &path,
            ContainerOptions {
                argon2: Argon2Params::MIN,
                initial_garbage_chunks: GARBAGE_CHUNKS,
                padding_policy: PaddingPolicy::None,
                superblock_replicas: 1,
            },
        )
        .unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(hidden_volume::space::index::Namespace::SETTINGS, b"k", b"v")
            .unwrap();
        tx.commit().unwrap();
    }

    // Read-only, so the open runs no maintenance whose allocations
    // would be counted alongside the scan's.
    let mut c = Container::open_readonly(&path).unwrap();
    COUNTING.store(true, Ordering::Relaxed);
    let space = c.open_space_constant_time(b"pw").unwrap();
    COUNTING.store(false, Ordering::Relaxed);
    drop(space);

    let aead = AEAD_ALLOCS.load(Ordering::Relaxed);
    let equalizer = EQUALIZER_ALLOCS.load(Ordering::Relaxed);

    // Calibration first: the scan has to have trial-decrypted the whole
    // file, or "the equalizer did not allocate" would be true because
    // the equalizer never ran.
    assert!(
        aead as u64 >= GARBAGE_CHUNKS,
        "calibration failed: only {aead} per-chunk AEAD buffers over \
         {GARBAGE_CHUNKS} garbage chunks — the constant-time scan did \
         not try every chunk, so this fixture proves nothing about the \
         equalizer"
    );

    // The finding. One buffer per rejected chunk puts this at about
    // GARBAGE_CHUNKS; a reused one puts it at zero. The slack is for an
    // unrelated allocation that happens to be exactly this size.
    let budget = GARBAGE_CHUNKS as usize / 8;
    assert!(
        equalizer < budget,
        "the timing equalizer made {equalizer} allocations of \
         {EQUALIZER_SIZE} bytes across {GARBAGE_CHUNKS} garbage chunks \
         (budget {budget}) — it is still allocating a buffer per \
         rejected chunk, against {aead} AEAD trials"
    );
}
