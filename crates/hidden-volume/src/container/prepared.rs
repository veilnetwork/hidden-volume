//! Host metadata repair before an atomic compaction is published.
//!
//! Repacking changes exported space keys. A host that stores references to
//! those keys must repair them in the staged container, not after the rename.
//! This handshake extends the existing rewrite writer; its source lock,
//! cancellation checks, temporary-file ownership and publication checks remain
//! those of the ordinary compactor.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender};
use std::thread::JoinHandle;

use zeroize::Zeroizing;

use super::{Container, RepackOptions, atomic_rewrite_under_source_lock};
use crate::cancel::CancelToken;
use crate::{Error, Result};

/// An unpublished encrypted replacement, with its source held read-only under
/// the ordinary exclusive container lock.
///
/// Authenticate and edit spaces at [Self::staged_path], then close every staged
/// handle before [Self::commit]. No password or old-container backup journal is
/// written. Before commit, aborting or losing the process leaves the original
/// container unchanged; an abrupt process exit may leave the same encrypted
/// temporary file as an interrupted ordinary rewrite.
///
/// Dropping without committing requests cancellation. Use [Self::abort] when
/// the caller must wait for cleanup before deleting or reopening the source.
#[must_use = "commit the prepared compaction, or abort it and retain the source"]
pub struct PreparedCompaction {
    staged_path: PathBuf,
    decision: Option<SyncSender<bool>>,
    worker: Option<JoinHandle<Result<()>>>,
    cancel: CancelToken,
}

impl std::fmt::Debug for PreparedCompaction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Paths and worker state are not diagnostic report fields.
        formatter
            .debug_struct("PreparedCompaction")
            .finish_non_exhaustive()
    }
}

fn finish_worker(worker: JoinHandle<Result<()>>) -> Result<()> {
    worker
        .join()
        .map_err(|_| Error::Internal("prepared compaction worker panicked"))?
}

impl PreparedCompaction {
    /// The encrypted replacement. The host must use its usual authenticated
    /// container APIs and keep this path within the trusted private directory.
    pub fn staged_path(&self) -> &Path {
        &self.staged_path
    }

    fn finish(&mut self, publish: bool) -> Result<()> {
        if let Some(decision) = self.decision.take() {
            // If the worker has already gone away, its result below carries
            // the authoritative failure rather than a channel error.
            let _ = decision.send(publish);
        }
        let worker = self
            .worker
            .take()
            .ok_or(Error::Internal("prepared compaction already finished"))?;
        finish_worker(worker)
    }

    /// Publish only after host metadata is repaired and all staged handles
    /// are closed. The ordinary typed post-rename outcomes are preserved.
    pub fn commit(mut self) -> Result<()> {
        self.finish(true)
    }

    /// Wait until the worker has discarded its replacement and released the
    /// source. Cleanup failures remain errors, with the source still unchanged.
    pub fn abort(mut self) -> Result<()> {
        self.cancel.cancel();
        match self.finish(false) {
            Err(Error::Cancelled) => Ok(()),
            Err(error) => Err(error),
            Ok(()) => Err(Error::Internal("aborted prepared compaction published")),
        }
    }
}

impl Drop for PreparedCompaction {
    fn drop(&mut self) {
        if let Some(decision) = self.decision.take() {
            self.cancel.cancel();
            let _ = decision.send(false);
        }
        // A forgotten capability must never grant publication. Do not block a
        // foreign-runtime finalizer on filesystem IO; explicit abort joins.
    }
}

impl Container {
    /// Prepare the ordinary password-preserving compaction without publishing
    /// it, allowing a host to repair encrypted references to the new space keys.
    ///
    /// Spaces without a supplied password are still dropped. This does not
    /// discover hidden spaces or preserve old exported keys.
    pub fn prepare_compact_known(
        path: &Path,
        passwords: &[&[u8]],
        options: RepackOptions,
    ) -> Result<PreparedCompaction> {
        Self::prepare_compact_known_cancellable(path, passwords, options, &CancelToken::new())
    }

    /// The shared token can also cancel the copying stage before preparation
    /// returns. Cancellation after preparation still requires abort/commit (or
    /// dropping the capability) to release the waiting worker.
    pub fn prepare_compact_known_cancellable(
        path: &Path,
        passwords: &[&[u8]],
        options: RepackOptions,
        cancel: &CancelToken,
    ) -> Result<PreparedCompaction> {
        let source = path.to_path_buf();
        let passwords = Zeroizing::new(passwords.iter().map(|p| p.to_vec()).collect::<Vec<_>>());
        let worker_cancel = cancel.clone();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (decision_tx, decision_rx) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("hv-prepared-compaction".into())
            .spawn(move || {
                atomic_rewrite_under_source_lock(
                    &source,
                    "hv-compact",
                    Some(&worker_cancel),
                    move |src, temporary, cancel| {
                        {
                            let mapping: Vec<_> = passwords
                                .iter()
                                .map(|p| (p.as_slice(), p.as_slice()))
                                .collect();
                            Container::repack_into_dest(src, temporary, &mapping, options, cancel)?;
                        }
                        // The host repair needs its own credentials; native
                        // copying no longer needs this additional copy.
                        drop(passwords);
                        if ready_tx.send(temporary.to_path_buf()).is_err() {
                            return Err(Error::Cancelled);
                        }
                        match decision_rx.recv() {
                            Ok(true) => Ok(()),
                            _ => Err(Error::Cancelled),
                        }
                    },
                )
            })
            .map_err(Error::Io)?;
        match ready_rx.recv() {
            Ok(staged_path) => Ok(PreparedCompaction {
                staged_path,
                decision: Some(decision_tx),
                worker: Some(worker),
                cancel: cancel.clone(),
            }),
            Err(_) => match finish_worker(worker) {
                Err(error) => Err(error),
                Ok(()) => Err(Error::Internal("compaction prepared no replacement")),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2Params;

    #[test]
    fn dropping_uncommitted_capability_never_publishes() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("fixture.hv");
        {
            let mut container = Container::create(&source, Argon2Params::MIN).unwrap();
            container.create_space(b"fixture-password").unwrap();
        }
        let before = std::fs::read(&source).unwrap();
        let mut plan = Container::prepare_compact_known(
            &source,
            &[b"fixture-password"],
            RepackOptions::default(),
        )
        .unwrap();
        // Keep only a test-side completion witness; Drop still owns the
        // decision channel and cancellation token.
        let worker = plan.worker.take().unwrap();
        drop(plan);
        assert!(matches!(finish_worker(worker), Err(Error::Cancelled)));
        assert_eq!(std::fs::read(&source).unwrap(), before);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        Container::open(&source).unwrap();
    }
}
