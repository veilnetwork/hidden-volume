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

    /// True if a space with this per-space `container_id` is already hosted.
    ///
    /// Hosting the same space through two ids is a data-loss trap: each
    /// `SpaceState` computes its next commit `seq` from its own (now stale)
    /// superblock, so two commits — one per handle — both land at the same
    /// `seq` with different payloads, breaking the "same-seq replicas are
    /// bit-equal" open invariant. On reopen the first-wins selection keeps one
    /// and silently discards the other acknowledged commit (and a debug build
    /// panics on the divergence assertion). Guard against it up front.
    fn already_hosts(&self, container_id: &[u8; 32]) -> bool {
        self.spaces.iter().flatten().any(|state| {
            // Constant-time compare is unnecessary: the caller holds the keys.
            &state.container_id == container_id
        })
    }

    /// Open an existing space by its [`SpaceKeys`] and host it; returns its
    /// **space id** (a small index used by [`Self::with_space`]). Returns
    /// [`Error::AuthFailed`] if no space in the container matches the keys, or
    /// [`Error::SpaceAlreadyExists`] if that space is already hosted here.
    pub fn open_space(&mut self, keys: SpaceKeys) -> Result<usize> {
        if self.already_hosts(&keys.container_id) {
            return Err(Error::SpaceAlreadyExists);
        }
        let state = scan_and_recover(&mut self.container.file, keys)?;
        let state = self.finalize_open(state)?;
        self.spaces.push(Some(state));
        Ok(self.spaces.len() - 1)
    }

    /// Run the post-open work a single-space open runs, so hosting a space
    /// here is not quietly weaker than opening it through [`Container`].
    ///
    /// `Container::open_space*` vacuums orphans on every writable handle
    /// (`open_space_with_keys_inner_opts`) precisely so that values a previous
    /// session deleted or overwrote stop being decryptable — the old index
    /// nodes are still valid AEAD, so anyone who later obtains the password
    /// and an old snapshot of the file can read them back. Hosting through
    /// `MultiSpace` went straight from `scan_and_recover` to a stored state
    /// and skipped it, so a host that opens every identity this way — which is
    /// what xVeil's all-online mode does, for every identity, every unlock —
    /// never scrubbed anything at all.
    ///
    /// Read-only hosts are left alone: `vacuum_orphans` is strict and answers
    /// `Err(ReadOnly)` under a shared lock, and refusing to open a container
    /// someone mounted read-only would be a worse bug than the one this fixes.
    fn finalize_open(&mut self, state: SpaceState) -> Result<SpaceState> {
        if self.container.is_readonly() {
            return Ok(state);
        }
        let mut space = Space::from_state(&mut self.container.file, state);
        let vacuumed = space.vacuum_orphans();
        // Take the state back BEFORE propagating: losing it on a vacuum error
        // would drop the caller's space entirely, which is a far larger
        // failure than the scrub that did not happen.
        let state = space.into_state();
        vacuumed?;
        Ok(state)
    }

    /// Constant-time-scan variant of [`Self::open_space`]. Equalizes the
    /// discovery scan so the host time can't leak which space (or none) matched
    /// — the F-TM1 mitigation, for hosts that open in a coercion-prone setting.
    /// Returns [`Error::AuthFailed`] if no space in the container matches, or
    /// [`Error::SpaceAlreadyExists`] if that space is already hosted here.
    pub fn open_space_constant_time(&mut self, keys: SpaceKeys) -> Result<usize> {
        if self.already_hosts(&keys.container_id) {
            return Err(Error::SpaceAlreadyExists);
        }
        let state = scan_and_recover_constant_time(&mut self.container.file, keys)?;
        let state = self.finalize_open(state)?;
        self.spaces.push(Some(state));
        Ok(self.spaces.len() - 1)
    }

    /// Create a new space in the container by its [`SpaceKeys`] and host it;
    /// returns its space id. Returns [`Error::SpaceAlreadyExists`] if the keys
    /// already map to a space (on disk or already hosted here).
    pub fn create_space(&mut self, keys: SpaceKeys) -> Result<usize> {
        if self.already_hosts(&keys.container_id) {
            return Err(Error::SpaceAlreadyExists);
        }
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

    /// Override the shared container's post-commit padding policy. Applies to
    /// future commits from any hosted space.
    pub fn set_padding_policy(&mut self, policy: crate::padding::PaddingPolicy) -> Result<()> {
        self.container.set_padding_policy(policy)
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
