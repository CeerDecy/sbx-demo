//! On-disk daemon state: the index high-water mark and one record per sandbox.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Persisted between runs in `config.state`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    /// One past the highest index ever handed out; only used by rollback.
    pub next_index: u32,
    /// Sandboxes this daemon created, as last known.
    pub entries: Vec<SandboxRecord>,
}

/// What the daemon knows about one sandbox.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxRecord {
    pub id: String,
    /// Private copy of the bundle, also the runsc bundle directory.
    pub bundle: PathBuf,
    pub netns: String,
    /// Host end of the veth pair.
    pub veth: String,
    pub ident: String,
    pub index: u32,
}
