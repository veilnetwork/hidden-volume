"""Python ctypes counterpart of `ffi_overhead_bench.dart`.

Runs the same workload (create / get / commit / header_info) so that
the dart:ffi numbers can be compared against a reference ctypes-based
binding driving the same uniffi 0.31 cdylib.

Run from the repo root:
    python experimental/flutter_plugin/hidden_volume/bench/ffi_overhead_bench.py
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
BINDINGS_PY = REPO_ROOT / "bindings" / "python"

# Ensure the cdylib is co-located next to hidden_volume_ffi.py so the
# stock loader (`uniffi_lib_init`) finds it on Windows.
DLL_NAME = "hidden_volume_ffi.dll"
SRC_DLL = REPO_ROOT / "target" / "release" / DLL_NAME
DST_DLL = BINDINGS_PY / DLL_NAME
if not DST_DLL.exists() or DST_DLL.stat().st_mtime < SRC_DLL.stat().st_mtime:
    shutil.copy2(SRC_DLL, DST_DLL)

sys.path.insert(0, str(BINDINGS_PY))
import hidden_volume_ffi as hv  # noqa: E402

OPS_PER_SAMPLE = 200
SAMPLES = 5


def report(label: str, sample_secs: list[float], ops_per_sample: int) -> None:
    per_op_us = sorted(s / ops_per_sample * 1e6 for s in sample_secs)
    print(
        f"{label:<36}  per-op: "
        f"min={per_op_us[0]:.2f}us  "
        f"p50={per_op_us[len(per_op_us)//2]:.2f}us  "
        f"max={per_op_us[-1]:.2f}us  "
        f"({SAMPLES} samples x {ops_per_sample} ops)"
    )


def bench_create(tmp: Path) -> None:
    samples: list[float] = []
    for i in range(SAMPLES):
        path = tmp / f"create_{i}.bin"
        t0 = time.perf_counter()
        s = hv.SpaceHandle.create(
            path=str(path),
            password=b"bench",
            argon=hv.ArgonPreset.LIGHT,
            initial_garbage_chunks=0,
            superblock_replicas=3,
        )
        samples.append(time.perf_counter() - t0)
        del s  # __del__ frees the handle
    report("create (Argon2 light + 1 init commit)", samples, 1)


def bench_get_commit(tmp: Path) -> None:
    path = tmp / "getcommit.bin"
    space = hv.SpaceHandle.create(
        path=str(path),
        password=b"bench",
        argon=hv.ArgonPreset.LIGHT,
        initial_garbage_chunks=0,
        superblock_replicas=3,
    )
    keys = [f"k{i}".encode() for i in range(OPS_PER_SAMPLE)]
    space.commit([
        hv.WriteOp.PUT(namespace=1, key=k, value=f"v{i}".encode())
        for i, k in enumerate(keys)
    ])

    get_samples: list[float] = []
    for _ in range(SAMPLES):
        t0 = time.perf_counter()
        for k in keys:
            space.get(namespace=1, key=k)
        get_samples.append(time.perf_counter() - t0)
    report("get  (200 reads/sample)", get_samples, OPS_PER_SAMPLE)

    commit_samples: list[float] = []
    for s in range(SAMPLES):
        t0 = time.perf_counter()
        for i in range(OPS_PER_SAMPLE):
            space.commit([
                hv.WriteOp.PUT(
                    namespace=2,
                    key=f"c{s}_{i}".encode(),
                    value=b"v",
                )
            ])
        commit_samples.append(time.perf_counter() - t0)
    report("commit (1 KV + fsync per call)", commit_samples, OPS_PER_SAMPLE)
    del space


def bench_header_info(tmp: Path) -> None:
    path = tmp / "header.bin"
    s = hv.SpaceHandle.create(
        path=str(path),
        password=b"bench",
        argon=hv.ArgonPreset.LIGHT,
        initial_garbage_chunks=0,
        superblock_replicas=3,
    )
    del s
    samples: list[float] = []
    for _ in range(SAMPLES):
        t0 = time.perf_counter()
        for _ in range(OPS_PER_SAMPLE):
            hv.header_info(path=str(path))
        samples.append(time.perf_counter() - t0)
    report("header_info (200 reads/sample)", samples, OPS_PER_SAMPLE)


def main() -> None:
    print(f"cdylib: {SRC_DLL}")
    print()
    with tempfile.TemporaryDirectory(prefix="hv_bench_") as d:
        tmp = Path(d)
        bench_create(tmp)
        bench_get_commit(tmp)
        bench_header_info(tmp)


if __name__ == "__main__":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    main()
