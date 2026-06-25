//! Multi-space hosting: hold several spaces of ONE container file open at the
//! same time, under that file's single exclusive lock.
//!
//! The single-space API ([`crate::Container::open_space`]) returns a
//! [`Space`] that borrows the container file for its whole lifetime, so only
//! one space can be open at once. That is the right shape when a host acts as
//! exactly one identity. A host that runs **several identities at once** (one
//! network node per identity, all over a single deniable container) needs every
//! identity's space open simultaneously.
//!
//! [`MultiSpace`] provides that by holding each space's recovered
//! `SpaceState` *detached* from the file, and binding one state to the file only
//! for the duration of a single operation (via the crate-internal
//! `Space::from_state`). Because every operation goes through
//! `&mut self`, writes to different spaces are serialized — which is exactly
//! what the single-writer file lock requires — while all spaces stay open (no
//! re-scan, no re-derivation) between operations.

use crate::container::Container;
use crate::crypto::SpaceKeys;
use crate::open::{scan_and_recover, scan_and_recover_constant_time};
use crate::space::{Space, SpaceState};
use crate::{Error, Result};

/// Several spaces of one container, hosted open at once under a single file
/// lock. Create one with [`MultiSpace::new`] over an already-open
/// [`Container`], then add spaces with [`MultiSpace::open_space`] /
/// [`MultiSpace::create_space`] and operate on each via
/// [`MultiSpace::with_space`].
pub struct MultiSpace {
    container: Container,
    /// Index = space id. `None` only transiently while a space is bound to the
    /// file inside [`Self::with_space`].
    spaces: Vec<Option<SpaceState>>,
}

impl core::fmt::Debug for MultiSpace {
    /// Redacted: never prints `SpaceState` (keys / plaintext-bearing state).
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MultiSpace")
            .field("spaces", &self.spaces.len())
            .finish_non_exhaustive()
    }
}

impl MultiSpace {
    /// Wrap an open [`Container`] (it already holds the file's exclusive lock).
    /// No spaces are hosted yet.
    #[must_use]
    pub fn new(container: Container) -> Self {
        Self {
            container,
            spaces: Vec::new(),
        }
    }

    /// Derive a space's [`SpaceKeys`] from its `password` (one Argon2id pass).
    /// The keys can be cached and later handed to [`Self::open_space`] to host
    /// the space without re-running Argon2.
    pub fn derive_space_keys(&self, password: &[u8]) -> Result<SpaceKeys> {
        self.container.derive_space_keys(password)
    }

    /// Open an existing space by its [`SpaceKeys`] and host it; returns its
    /// **space id** (a small index used by [`Self::with_space`]). Returns
    /// [`Error::AuthFailed`] if no space in the container matches the keys.
    pub fn open_space(&mut self, keys: SpaceKeys) -> Result<usize> {
        let state = scan_and_recover(&mut self.container.file, keys)?;
        self.spaces.push(Some(state));
        Ok(self.spaces.len() - 1)
    }

    /// Constant-time-scan variant of [`Self::open_space`]. Equalizes the
    /// discovery scan so the host time can't leak which space (or none) matched
    /// — the F-TM1 mitigation, for hosts that open in a coercion-prone setting.
    /// Returns [`Error::AuthFailed`] if no space in the container matches.
    pub fn open_space_constant_time(&mut self, keys: SpaceKeys) -> Result<usize> {
        let state = scan_and_recover_constant_time(&mut self.container.file, keys)?;
        self.spaces.push(Some(state));
        Ok(self.spaces.len() - 1)
    }

    /// Create a new space in the container by its [`SpaceKeys`] and host it;
    /// returns its space id. Returns [`Error::SpaceAlreadyExists`] if the keys
    /// already map to a space.
    pub fn create_space(&mut self, keys: SpaceKeys) -> Result<usize> {
        let state = Space::create(&mut self.container.file, keys)?.into_state();
        self.spaces.push(Some(state));
        Ok(self.spaces.len() - 1)
    }

    /// Number of hosted spaces.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spaces.len()
    }

    /// True when no spaces are hosted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spaces.is_empty()
    }

    /// Bind hosted space `id` to the container file, run `f` against the usable
    /// [`Space`], then detach it again. The file borrow — and the exclusive lock
    /// it represents — is held only for the duration of `f`, so a later
    /// [`Self::with_space`] on a *different* id reuses the same file serially.
    ///
    /// Returns [`Error::Malformed`] if `id` is not a hosted space.
    ///
    /// **Panic note.** If `f` panics, the space's state is not restored (the
    /// slot stays `None` and further calls on that id return `Malformed`); the
    /// other hosted spaces are unaffected. Operations here do not panic in
    /// normal use — same posture as the single-space handle.
    pub fn with_space<R>(&mut self, id: usize, f: impl FnOnce(&mut Space<'_>) -> R) -> Result<R> {
        let state = self
            .spaces
            .get_mut(id)
            .and_then(Option::take)
            .ok_or(Error::Malformed("no such space id"))?;
        let mut space = Space::from_state(&mut self.container.file, state);
        let out = f(&mut space);
        self.spaces[id] = Some(space.into_state());
        Ok(out)
    }
}
