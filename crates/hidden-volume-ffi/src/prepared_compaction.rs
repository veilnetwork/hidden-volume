//! Foreign ownership of an unpublished replacement container.

use std::sync::{Arc, Mutex};

use hidden_volume::Container;
use hidden_volume::container::{PreparedCompaction, RepackOptions};
use zeroize::Zeroizing;

use crate::{HvError, HvResult, poisoned_mutex};

enum State {
    Fresh,
    Prepared(PreparedCompaction),
    Finished,
}

/// Owns an atomic rewrite until the host repairs its encrypted metadata.
///
/// Allocate this capability BEFORE dispatching expensive work. The host keeps
/// its original reference while workers borrow cloned references. On any
/// failed/lost worker reply, call [`Self::abort`] and wait before reopening or
/// deleting the source. Dropping the last reference never grants publication.
#[derive(uniffi::Object)]
pub struct PreparedCompactionHandle {
    state: Mutex<State>,
}

#[uniffi::export]
impl PreparedCompactionHandle {
    /// Allocate an empty capability, without opening a file or retaining keys.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::Fresh),
        })
    }

    /// Copy the supplied spaces into an encrypted, unpublished replacement.
    ///
    /// Returns its private path for ordinary authenticated metadata repair.
    /// Spaces not unlocked by a supplied password are discarded. Exported keys
    /// change. Source posture, locking and publication checks are unchanged.
    pub fn prepare(&self, path: String, passwords: Vec<Vec<u8>>) -> HvResult<String> {
        let passwords: Vec<_> = passwords.into_iter().map(Zeroizing::new).collect();
        let mut state = self.state.lock().map_err(|_| poisoned_mutex())?;
        if !matches!(*state, State::Fresh) {
            return Err(HvError::Internal(
                "compaction capability already used".into(),
            ));
        }
        // A failed preparation is terminal too: a late worker must never
        // restart copying after an abort has drained this capability.
        *state = State::Finished;
        let refs: Vec<_> = passwords.iter().map(|p| p.as_slice()).collect();
        let plan = Container::prepare_compact_known(
            std::path::Path::new(&path),
            &refs,
            RepackOptions::default(),
        )?;
        let Some(staged) = plan.staged_path().to_str().map(str::to_owned) else {
            plan.abort()?;
            return Err(HvError::Malformed(
                "prepared container path is not UTF-8".into(),
            ));
        };
        *state = State::Prepared(plan);
        Ok(staged)
    }

    /// Publish AFTER the host repairs metadata and closes all staged handles.
    /// Typed post-publication durability/alias warnings retain their meaning.
    pub fn commit(&self) -> HvResult<()> {
        let mut state = self.state.lock().map_err(|_| poisoned_mutex())?;
        let State::Prepared(plan) = std::mem::replace(&mut *state, State::Finished) else {
            return Err(HvError::Internal("compaction is not prepared".into()));
        };
        // Keep the mutex THROUGH the join. A concurrent abort must not report
        // quiescence while a consumed plan could still rename the source.
        plan.commit()?;
        Ok(())
    }

    /// Discard an unpublished replacement and wait for source-lock release.
    /// Idempotent; also prevents a not-yet-started worker from preparing later.
    /// An already completed publication is not undone.
    pub fn abort(&self) -> HvResult<()> {
        let mut state = self.state.lock().map_err(|_| poisoned_mutex())?;
        if let State::Prepared(plan) = std::mem::replace(&mut *state, State::Finished) {
            plan.abort()?;
        }
        Ok(())
    }
}
