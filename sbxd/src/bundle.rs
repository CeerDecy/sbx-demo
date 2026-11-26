//! Per-sandbox copies of an OCI bundle.
//!
//! Each sandbox gets its own copy of the base bundle under `bundles/`, so the
//! shared base is never mutated and the sandbox's `config.json` can point at
//! its own network namespace.

use crate::{error, files};
use anyhow::{Context, Result};
use sbx_proto::ErrorCode;
use serde_json::{Value, json};
use std::{fs, io, path::Path};

/// Ensures `private` holds a usable copy of `base` for namespace `ns` and that
/// its `config.json` is patched to match.
pub fn prepare(base: &Path, private: &Path, ns: &str) -> Result<()> {
    if private.exists() {
        let marker = read_marker(private)?;
        if marker
            .as_deref()
            .is_some_and(|m| m.trim_end() != base.to_string_lossy())
        {
            return Err(error::coded(
                ErrorCode::AlreadyExists,
                format!(
                    "{} exists from a different base bundle ({})",
                    private.display(),
                    marker.as_deref().unwrap_or("").trim()
                ),
            ));
        }
    } else {
        files::copy_tree(base, private)?;
    }
    files::atomic_write(
        &private.join(".base-bundle"),
        format!("{}\n", base.display()).as_bytes(),
    )?;
    patch_config(&private.join("config.json"), ns)
}

/// The base bundle a private bundle was copied from, if the marker survived.
fn read_marker(private: &Path) -> Result<Option<String>> {
    match fs::read_to_string(private.join(".base-bundle")) {
        Ok(marker) => Ok(Some(marker)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Points the bundle at `ns` and replaces its init process with an idle shell,
/// so `runsc exec` can drive it later.
fn patch_config(path: &Path, ns: &str) -> Result<()> {
    let mut config: Value = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("read {}", path.display()))?,
    )?;
    let namespaces = config
        .pointer_mut("/linux/namespaces")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            error::coded(
                ErrorCode::InvalidRequest,
                "config.json has no linux.namespaces array",
            )
        })?;
    let mut found = false;
    for namespace in namespaces {
        if namespace.get("type").and_then(Value::as_str) == Some("network") {
            *namespace = json!({"type":"network", "path":format!("/var/run/netns/{ns}")});
            found = true;
        }
    }
    if !found {
        return Err(error::coded(
            ErrorCode::InvalidRequest,
            "config.json has no network namespace entry",
        ));
    }
    if !config.get("process").is_some_and(Value::is_object) {
        return Err(error::coded(
            ErrorCode::InvalidRequest,
            "config.json has no process object",
        ));
    }
    config["process"]["args"] = json!(["/bin/sh", "-c", "while :; do sleep 3600; done"]);
    config["process"]["terminal"] = json!(false);
    // Replace the inode, never write through the base bundle's hardlink.
    files::atomic_write(path, &serde_json::to_vec_pretty(&config)?)
}
