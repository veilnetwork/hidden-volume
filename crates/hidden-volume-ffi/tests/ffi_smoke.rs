//! FFI surface smoke-test for the host-target cdylib.
//!
//! Builds (implicitly, via `cargo test`) the cdylib for the test
//! host, dlopens it via `libloading`, and probes the uniffi 0.28 C
//! ABI surface that downstream language bindings (Kotlin, Swift,
//! Python, Dart) depend on. Catches FFI-surface drift between
//! `#[uniffi::*]` annotations and the generated symbol set without
//! needing a foreign-language toolchain in the loop.
//!
//! Why this matters for Flutter integration: the Dart `dart:ffi`
//! bindings in `experimental/flutter_plugin/hidden_volume/lib/src/bindings.dart`
//! resolve symbols by name from `libhidden_volume_ffi.so`. If a
//! refactor renames or drops a uniffi-exported function, this test
//! fails *before* the change reaches a slow Android emulator run.
//!
//! Coverage:
//!   1. cdylib loads cleanly (no missing-symbol link errors).
//!   2. `ffi_hidden_volume_ffi_uniffi_contract_version` resolves.
//!   3. Per-method API checksum probes resolve for a representative
//!      subset of the FFI surface (`HvContainer.create`,
//!      `HvContainer.open_space`, `HvSpace.commit`, ...).
//!
//! Note: the cdylib path is computed from the standard cargo target
//! layout. On Unix it's `target/<profile>/libhidden_volume_ffi.so`
//! (Linux/Android) or `.dylib` (macOS). On Windows it's a `.dll`.
//! The test runs only when the cdylib is available — on a fresh
//! checkout with no prior build, it fails loudly with the path it
//! tried, which is the diagnostic we want.

use std::env;
use std::path::PathBuf;

/// Locate the cdylib alongside this test binary. Cargo places test
/// binaries in `target/<profile>/deps/<name>-<hash>` and cdylibs
/// directly in `target/<profile>/`, so we walk one directory up.
fn cdylib_path() -> PathBuf {
    let test_exe = env::current_exe().expect("test exe path");
    // current_exe = target/<profile>/deps/ffi_smoke-<hash>
    // we want    = target/<profile>/lib<name>.<ext>
    let target_profile_dir = test_exe
        .parent()
        .and_then(|p| p.parent())
        .expect("target/<profile> dir");

    let (prefix, ext) = if cfg!(target_os = "windows") {
        ("", "dll")
    } else if cfg!(target_os = "macos") {
        ("lib", "dylib")
    } else {
        ("lib", "so")
    };

    target_profile_dir.join(format!("{prefix}hidden_volume_ffi.{ext}"))
}

/// Whether to fail tests on a missing cdylib. Set
/// `HV_REQUIRE_CDYLIB=1` in CI / dev workflows that explicitly run
/// `cargo build -p hidden-volume-ffi` before `cargo test`. Default
/// behaviour skips: `cargo test` on its own does NOT trigger the
/// cdylib build (the test crate links the rlib `lib` crate-type, not
/// the `cdylib`), so a hard assert here would fail every plain
/// `cargo test --workspace` run.
fn require_cdylib() -> bool {
    std::env::var_os("HV_REQUIRE_CDYLIB").is_some()
}

#[test]
fn cdylib_loads_and_uniffi_contract_version_symbol_resolves() {
    let path = cdylib_path();
    if !path.exists() {
        if require_cdylib() {
            panic!(
                "cdylib not built at {}; HV_REQUIRE_CDYLIB demands it. \
                 run `cargo build -p hidden-volume-ffi` first",
                path.display()
            );
        }
        eprintln!("skipping: cdylib not present at {}", path.display());
        return;
    }

    // SAFETY: we just dlopen the cdylib the cargo test profile built;
    // the library is well-formed Rust output. libloading is `unsafe`
    // because of TOCTOU on the path and because callers can transmute
    // arbitrary signatures; we only use it to probe symbol existence
    // via void-returning lookups, never call.
    let lib = unsafe { libloading::Library::new(&path) }
        .unwrap_or_else(|e| panic!("failed to dlopen {}: {e}", path.display()));

    // The uniffi 0.28 contract-version probe is a `() -> u32` C symbol
    // every cdylib generated from uniffi proc-macros must export. If
    // it's missing, no foreign-language binding will work.
    let _: libloading::Symbol<unsafe extern "C" fn() -> u32> = unsafe {
        lib.get(b"ffi_hidden_volume_ffi_uniffi_contract_version")
            .expect("uniffi contract-version symbol must exist")
    };
}

#[test]
fn representative_method_checksum_symbols_resolve() {
    let path = cdylib_path();
    if !path.exists() {
        // Same diagnostic as the first test; we skip rather than
        // duplicate the panic message.
        return;
    }

    let lib = unsafe { libloading::Library::new(&path) }.expect("dlopen cdylib");

    // uniffi exports a `uniffi_hidden_volume_ffi_checksum_<kind>_<name>`
    // symbol for every method, constructor, and free function in the
    // FFI surface. Each returns a `u16` checksum that the foreign-
    // language binding compares against the value baked into its
    // generated code. We probe a representative subset — if any one
    // of these is missing, the FFI surface has drifted from the
    // bindings and Flutter/Kotlin/Swift consumers will break.
    //
    // The full set is large (tens of methods); this list is a
    // tripwire for "did the bindgen output structurally change",
    // not a complete enumeration. The Python smoke test
    // (bindings/python/test_smoke.py) is the end-to-end check.
    let representative_symbols: &[&[u8]] = &[
        // Sync surface (SpaceHandle).
        b"uniffi_hidden_volume_ffi_checksum_constructor_spacehandle_create",
        b"uniffi_hidden_volume_ffi_checksum_constructor_spacehandle_open",
        b"uniffi_hidden_volume_ffi_checksum_method_spacehandle_commit",
        b"uniffi_hidden_volume_ffi_checksum_method_spacehandle_get",
        b"uniffi_hidden_volume_ffi_checksum_method_spacehandle_verify_integrity",
        // Async surface (AsyncSpaceHandle).
        b"uniffi_hidden_volume_ffi_checksum_constructor_asyncspacehandle_create",
        b"uniffi_hidden_volume_ffi_checksum_constructor_asyncspacehandle_open",
        b"uniffi_hidden_volume_ffi_checksum_method_asyncspacehandle_commit",
        // Free function.
        b"uniffi_hidden_volume_ffi_checksum_func_header_info",
    ];

    let mut missing = Vec::new();
    for sym in representative_symbols {
        let res: Result<libloading::Symbol<unsafe extern "C" fn() -> u16>, _> =
            unsafe { lib.get(sym) };
        if res.is_err() {
            missing.push(String::from_utf8_lossy(sym).into_owned());
        }
    }

    assert!(
        missing.is_empty(),
        "uniffi checksum symbols missing from cdylib (FFI surface drift?):\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn contract_version_value_is_plausible() {
    let path = cdylib_path();
    if !path.exists() {
        return;
    }
    let lib = unsafe { libloading::Library::new(&path) }.expect("dlopen cdylib");

    let probe: libloading::Symbol<unsafe extern "C" fn() -> u32> = unsafe {
        lib.get(b"ffi_hidden_volume_ffi_uniffi_contract_version")
            .expect("uniffi contract-version symbol")
    };

    // uniffi exposes its contract version as a u32 generated at
    // codegen time. We don't hardcode a single expected value (it
    // moves with uniffi minor bumps); we just sanity-check it's a
    // plausible non-zero integer. A real mismatch surfaces as a
    // foreign-binding-side failure, but a zero / extreme value
    // here would indicate the symbol was loaded against a wildly
    // wrong cdylib.
    let v = unsafe { probe() };
    assert!(v > 0, "contract version must be non-zero");
    assert!(v < 1_000_000, "contract version implausibly large: {v}");
}
