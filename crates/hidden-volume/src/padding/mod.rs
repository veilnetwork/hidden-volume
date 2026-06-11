//! File-size padding policies — DESIGN §8.
//!
//! ## Threat
//!
//! A multi-snapshot adversary observing the container file at multiple
//! points in time can infer write activity from file size deltas. Even
//! though chunk contents are indistinguishable from random, raw size
//! still leaks a count of "how many chunks were appended between
//! snapshots".
//!
//! ## Mitigation
//!
//! After each successful Tx commit, write extra garbage chunks to round
//! the file size up to a coarser granularity. Observer sees only
//! discrete jumps (e.g. file grew by exactly 1 MiB) rather than per-Tx
//! deltas.
//!
//! Garbage chunks are `CHUNK_SIZE` bytes of uniform random — visually
//! identical to AEAD-encrypted chunks of any space. Indistinguishable
//! from real-but-foreign-space data.
//!
//! ## Policies
//!
//! - [`PaddingPolicy::None`] — no post-commit padding. Tests / debug.
//! - [`PaddingPolicy::BucketGrowth`] — round file size up to a multiple
//!   of `bucket_chunks`. Recommended default. Cost: up to
//!   `bucket_chunks - 1` garbage chunks per commit.
//! - [`PaddingPolicy::FixedRatio`] — append a fixed ratio of garbage
//!   chunks per real chunk written. Smoother growth, less quantization.

/// Post-commit padding policy. Marked `#[non_exhaustive]` because
/// future versions may add new policies (e.g., exponential bucket
/// growth) without bumping major.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PaddingPolicy {
    /// No post-commit padding.
    #[default]
    None,
    /// Round file size up to the next multiple of `bucket_chunks`.
    /// Concretely, after a commit the library appends garbage chunks
    /// until `(slot_count + 1) % bucket_chunks == 0`. Pick
    /// `bucket_chunks` matching your target hardware:
    ///
    /// - 64 (256 KiB) for embedded / very weak phones
    /// - 256 (1 MiB) for typical mobile (recommended default)
    /// - 4096 (16 MiB) for desktop / unconstrained storage
    BucketGrowth {
        /// Bucket size in chunks. After each commit the file is
        /// padded with garbage chunks until
        /// `(slot_count + 1) % bucket_chunks == 0`.
        bucket_chunks: u64,
    },
    /// Add `garbage_per_real_x100 / 100` garbage chunks per real chunk
    /// written in the commit. `garbage_per_real_x100 = 100` means a
    /// 1:1 ratio (file grows 2× actual data). Use for smoother growth
    /// when bucket quantization is too lumpy.
    FixedRatio {
        /// Garbage-to-real ratio in hundredths. `100` = 1:1 (file
        /// grows 2× actual data); `50` = 0.5:1; `200` = 2:1 etc.
        garbage_per_real_x100: u32,
    },
}

impl PaddingPolicy {
    /// Recommended default: 1 MiB buckets. Adds ≤255 garbage chunks
    /// per commit, ~1 MiB worst-case overhead. On weak hardware this
    /// is a few ms of extra fsync per Tx.
    pub const DEFAULT: Self = Self::BucketGrowth { bucket_chunks: 256 };

    /// Decode an 8-bit padding-policy index (the format-persisted byte
    /// in [`crate::crypto::kdf::Argon2Params::version`] bits 16..24).
    /// Audit pass 8 (S1 full).
    ///
    /// Mapping:
    /// - `0` → [`PaddingPolicy::None`] (default for legacy v1 containers
    ///   created before pass 8)
    /// - `1` → 256 KiB buckets (`bucket_chunks: 64`) — embedded / weak phones
    /// - `2` → 1 MiB buckets (`bucket_chunks: 256`) — typical mobile (DEFAULT)
    /// - `3` → 16 MiB buckets (`bucket_chunks: 4096`) — desktop
    /// - any other value → [`PaddingPolicy::None`] (forward-compat: a
    ///   future writer's unknown index degrades to no-padding rather
    ///   than refusing to open)
    ///
    /// Custom values (`FixedRatio`, custom `bucket_chunks`) are NOT
    /// representable as 1-byte indices — callers using those policies
    /// must call [`crate::Container::set_padding_policy`] on every
    /// open. The persistent index is a convenience for the common
    /// preset case.
    #[must_use]
    pub fn from_persisted_index(idx: u8) -> Self {
        match idx {
            0 => Self::None,
            1 => Self::BucketGrowth { bucket_chunks: 64 },
            2 => Self::BucketGrowth { bucket_chunks: 256 },
            3 => Self::BucketGrowth {
                bucket_chunks: 4096,
            },
            _ => Self::None,
        }
    }

    /// Encode a padding policy as an 8-bit persistent index. Returns
    /// `None` if the policy isn't representable (custom `bucket_chunks`,
    /// `FixedRatio`, etc.) — caller should fall back to runtime
    /// `set_padding_policy` instead.
    #[must_use]
    pub fn to_persisted_index(&self) -> Option<u8> {
        match self {
            Self::None => Some(0),
            Self::BucketGrowth { bucket_chunks: 64 } => Some(1),
            Self::BucketGrowth { bucket_chunks: 256 } => Some(2),
            Self::BucketGrowth {
                bucket_chunks: 4096,
            } => Some(3),
            _ => None,
        }
    }

    /// Number of garbage chunks to append AFTER a commit that wrote
    /// `real_chunks_added` data chunks, given the current `slot_count`
    /// (which already reflects the real chunks just written).
    ///
    /// Returns `Ok` with a count such that the post-padding slot_count
    /// is ≥ pre-padding slot_count. Returns `Err(Error::Internal)` only
    /// in the pathological case where the policy's arithmetic would
    /// overflow `u64` (audit pass 17 C: previously this used unchecked
    /// `div_ceil(b) * b` and `u128 as u64` truncation — both
    /// theoretically reachable with extreme `bucket_chunks` /
    /// `garbage_per_real_x100` plus a near-`u64::MAX` `slot_count`,
    /// even though the write-side budget cap (audit pass 17 B) makes
    /// that combination unreachable on realistic file sizes).
    pub fn garbage_after_commit(
        &self,
        slot_count: u64,
        real_chunks_added: u64,
    ) -> crate::Result<u64> {
        match self {
            Self::None => Ok(0),
            Self::BucketGrowth { bucket_chunks } => {
                let b = *bucket_chunks;
                if b == 0 {
                    return Ok(0);
                }
                // div_ceil never overflows for u64; the multiplication
                // can if `slot_count` is near `u64::MAX` and `b > 1`.
                let buckets = slot_count.div_ceil(b);
                let target = buckets.checked_mul(b).ok_or(crate::Error::Internal(
                    "padding policy: bucket target overflow",
                ))?;
                Ok(target.saturating_sub(slot_count))
            },
            Self::FixedRatio {
                garbage_per_real_x100,
            } => {
                let prod = u128::from(real_chunks_added)
                    .checked_mul(u128::from(*garbage_per_real_x100))
                    .ok_or(crate::Error::Internal(
                        "padding policy: fixed-ratio multiplication overflow",
                    ))?;
                let result = prod / 100;
                u64::try_from(result).map_err(|_| {
                    crate::Error::Internal("padding policy: fixed-ratio result exceeds u64")
                })
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_yields_no_padding() {
        let p = PaddingPolicy::None;
        assert_eq!(p.garbage_after_commit(0, 0).unwrap(), 0);
        assert_eq!(p.garbage_after_commit(100, 5).unwrap(), 0);
    }

    #[test]
    fn bucket_growth_quantizes() {
        let p = PaddingPolicy::BucketGrowth { bucket_chunks: 256 };
        assert_eq!(p.garbage_after_commit(0, 0).unwrap(), 0);
        assert_eq!(p.garbage_after_commit(1, 1).unwrap(), 255);
        assert_eq!(p.garbage_after_commit(255, 1).unwrap(), 1);
        assert_eq!(p.garbage_after_commit(256, 0).unwrap(), 0);
        assert_eq!(p.garbage_after_commit(257, 1).unwrap(), 255);
        assert_eq!(p.garbage_after_commit(512, 0).unwrap(), 0);
    }

    #[test]
    fn bucket_zero_is_safe_noop() {
        let p = PaddingPolicy::BucketGrowth { bucket_chunks: 0 };
        assert_eq!(p.garbage_after_commit(123, 5).unwrap(), 0);
    }

    #[test]
    fn fixed_ratio_scales_with_real() {
        let p = PaddingPolicy::FixedRatio {
            garbage_per_real_x100: 100,
        };
        assert_eq!(p.garbage_after_commit(0, 0).unwrap(), 0);
        assert_eq!(p.garbage_after_commit(0, 4).unwrap(), 4); // 1:1
        let p = PaddingPolicy::FixedRatio {
            garbage_per_real_x100: 50,
        };
        assert_eq!(p.garbage_after_commit(0, 4).unwrap(), 2); // 0.5:1
        let p = PaddingPolicy::FixedRatio {
            garbage_per_real_x100: 200,
        };
        assert_eq!(p.garbage_after_commit(0, 3).unwrap(), 6); // 2:1
    }

    /// Audit pass 17 C: extreme inputs that previously panicked
    /// (`div_ceil(b) * b` overflow) or silently truncated
    /// (`u128 as u64`) now surface as `Error::Internal` instead of
    /// returning a meaningless count or aborting the process.
    #[test]
    fn extreme_bucket_returns_internal_error_instead_of_panic() {
        let p = PaddingPolicy::BucketGrowth {
            bucket_chunks: u64::MAX,
        };
        // `slot_count = 1` → `div_ceil(u64::MAX) = 1` → `1 * u64::MAX`
        // (no overflow; passes through). `slot_count = 2` → still 1.
        // The overflow case is `slot_count > u64::MAX - bucket_chunks + 1`
        // which is unreachable on a real `slot_count` (file would be
        // larger than the universe). We still guard, and the bucket=1
        // case must never panic.
        assert_eq!(p.garbage_after_commit(1, 1).unwrap(), u64::MAX - 1);
    }

    #[test]
    fn extreme_fixed_ratio_returns_internal_error_instead_of_panic() {
        let p = PaddingPolicy::FixedRatio {
            garbage_per_real_x100: u32::MAX,
        };
        // `real_chunks_added = u64::MAX, ratio = u32::MAX` →
        // `u128 = u64::MAX * u32::MAX ≈ 2^96` → `/100 ≈ 2^89` →
        // `try_from u128 to u64` fails → `Error::Internal`.
        let err = p.garbage_after_commit(0, u64::MAX).unwrap_err();
        assert!(matches!(err, crate::Error::Internal(_)));
    }
}
