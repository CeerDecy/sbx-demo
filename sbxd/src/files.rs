//! File-system helpers: atomic writes and bundle tree copies.

use crate::error;
use anyhow::Result;
use sbx_proto::ErrorCode;
use std::{
    fs,
    io::Write,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

/// Replaces `path` with `bytes` by writing a sibling file and renaming it, so
/// a reader never observes a half-written file.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".sbxd-{}-{}", std::process::id(), unique_id()));
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        if let Ok(meta) = fs::metadata(path) {
            file.set_permissions(meta.permissions())?;
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    let _ = fs::remove_file(&temporary);
    result
}

/// Process-local counter used to keep temporary names unique.
pub fn unique_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Copies `source` into `destination`, hardlinking regular files where the
/// two live on the same filesystem. Existing entries are left alone.
pub fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let dest_path = destination.join(entry.file_name());
        if fs::symlink_metadata(&dest_path).is_ok() {
            continue;
        }
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(source_path)?, dest_path)?;
        } else if metadata.is_dir() {
            copy_tree(&source_path, &dest_path)?;
        } else if metadata.is_file() {
            if fs::hard_link(&source_path, &dest_path).is_err() {
                fs::copy(&source_path, &dest_path)?;
                fs::set_permissions(dest_path, metadata.permissions())?;
            }
        } else {
            return Err(error::coded(
                ErrorCode::IoError,
                format!("unsupported bundle file: {}", source_path.display()),
            ));
        }
    }
    fs::set_permissions(destination, fs::metadata(source)?.permissions())?;
    Ok(())
}
