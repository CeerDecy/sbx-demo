//! Sandbox lifecycle: create, list, run and remove gVisor sandboxes.

use crate::{
    bundle, command, config::Config, daemon::Daemon, error, files, net, state::SandboxRecord,
};
use anyhow::{Context, Result};
use sbx_proto::ErrorCode;
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

/// Sandbox ids are lowercase letters, digits and dash, at most 31 bytes.
pub fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 31
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Whether runsc currently knows a sandbox with this id.
pub fn exists(c: &Config, id: &str) -> Result<bool> {
    let output = command::output(&c.runsc, &["--root", &c.runsc_root, "list"])?;
    if !output.status.success() {
        return Err(error::coded(
            ErrorCode::CommandFailed,
            format!("runsc list: {}", String::from_utf8_lossy(&output.stderr)),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1)
        .any(|line| line.split_whitespace().next() == Some(id)))
}

/// Creates a sandbox and starts its init process.
///
/// On any failure the partially built sandbox is torn down again by
/// [`Rollback`]: namespace, runsc sandbox, state entry and reserved index.
pub fn create(
    daemon: &Daemon,
    id: String,
    bundle: Option<String>,
    gpu: bool,
) -> Result<SandboxRecord> {
    let c = &daemon.config;
    if !valid_id(&id) {
        return Err(error::coded(
            ErrorCode::InvalidId,
            format!("invalid id '{id}' (lowercase letters, digits, dash)"),
        ));
    }
    if gpu {
        return Err(error::coded(
            ErrorCode::NotImplemented,
            "GPU device injection is not implemented",
        ));
    }
    let base = bundle
        .map(PathBuf::from)
        .unwrap_or_else(|| c.default_bundle.clone());
    if !base.join("rootfs").is_dir() {
        return Err(error::coded(
            ErrorCode::IoError,
            format!("no rootfs under {}", base.display()),
        ));
    }
    let _lifecycle = daemon.lifecycle.lock().expect("lifecycle lock poisoned");
    let ns = format!("sbx-{id}");
    let veth = format!("v-{id}");
    if net::namespace_exists(&ns) || exists(c, &id)? {
        return Err(error::coded(
            ErrorCode::AlreadyExists,
            format!("sandbox or network namespace '{id}' already exists"),
        ));
    }
    let (old_index, index) = {
        let state = daemon.state.lock().expect("state lock poisoned");
        let recorded: Vec<u32> = state.entries.iter().map(|record| record.index).collect();
        (state.next_index, net::allocate_index(&recorded)?)
    };
    net::create_namespace(&ns)?;
    let mut rollback = Rollback {
        active: true,
        ns: ns.clone(),
        daemon,
        old_index,
        started_id: None,
    };
    daemon.state.lock().expect("state lock poisoned").next_index = index + 1;
    net::attach_interface(&ns, &veth, &c.ident)?;
    // The datapath answers the gateway's ARP on this veth; without it the
    // sandbox cannot resolve its next hop. Failure rolls the sandbox back.
    daemon
        .ebpf
        .lock()
        .expect("ebpf lock poisoned")
        .attach(&veth)
        .with_context(|| format!("attach eBPF to {veth}"))?;
    let private_bundle = c.bundles.join(format!("sbx-{id}"));
    bundle::prepare(&base, &private_bundle, &ns)?;
    start(daemon, &id, &private_bundle)?;
    rollback.started_id = Some(id.clone());
    let record = SandboxRecord {
        id,
        bundle: private_bundle,
        netns: ns,
        veth,
        ident: c.ident.clone(),
        index,
    };
    daemon
        .state
        .lock()
        .expect("state lock poisoned")
        .entries
        .push(record.clone());
    daemon.persist()?;
    rollback.active = false;
    Ok(record)
}

/// Starts runsc detached on the prepared bundle and surfaces its stderr if it
/// refuses to come up.
fn start(daemon: &Daemon, id: &str, private_bundle: &Path) -> Result<()> {
    let c = &daemon.config;
    // A detached runsc child may retain stderr; a regular file cannot keep us
    // waiting for EOF. Unlink immediately, retaining the open descriptor.
    let stderr_path = std::env::temp_dir().join(format!(
        "sbxd-start-{}-{}",
        std::process::id(),
        files::unique_id()
    ));
    let stderr_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&stderr_path)?;
    fs::remove_file(&stderr_path)?;
    let mut command = Command::new(&c.runsc);
    if c.gpu {
        command.args([
            "--nvproxy",
            "--nvproxy-allowed-driver-capabilities=compute,utility",
        ]);
    }
    let status = command
        .args([
            "--platform=systrap",
            "--network=sandbox",
            "--root",
            &c.runsc_root,
            "run",
            "-detach",
            "-bundle",
        ])
        .arg(private_bundle)
        .arg(id)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file.try_clone()?))
        .status()?;
    if !status.success() {
        let mut file = stderr_file;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        return Err(error::coded(
            ErrorCode::CommandFailed,
            format!(
                "sandbox '{id}' failed to start: {}",
                String::from_utf8_lossy(&bytes).trim()
            ),
        ));
    }
    Ok(())
}

/// Lists what runsc reports, enriched with the sandbox's address and netns.
pub fn list(c: &Config) -> Result<Value> {
    let output = command::output(&c.runsc, &["--root", &c.runsc_root, "list"])?;
    if !output.status.success() {
        return Err(error::coded(
            ErrorCode::CommandFailed,
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }
    let mut result = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        let Some(id) = fields.first() else {
            continue;
        };
        let ns = format!("sbx-{id}");
        let address = command::output(
            "ip",
            &[
                "netns", "exec", &ns, "ip", "-4", "-o", "addr", "show", "eth0",
            ],
        )
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .nth(3)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "none".into());
        let netns = if net::namespace_exists(&ns) {
            ns
        } else {
            "(none)".into()
        };
        result.push(json!({"id":id,"status":fields.get(2).copied().unwrap_or("unknown"),"address":address,"netns":netns}));
    }
    Ok(json!(result))
}

/// Runs one command inside a sandbox and returns its exit code and streams.
pub fn run(c: &Config, id: String, argv: Vec<String>) -> Result<Value> {
    if !valid_id(&id) {
        return Err(error::coded(ErrorCode::InvalidId, "invalid id"));
    }
    if argv.is_empty() {
        return Err(error::coded(
            ErrorCode::InvalidRequest,
            "argv must not be empty",
        ));
    }
    let output = Command::new(&c.runsc)
        .args(["--root", &c.runsc_root, "exec", &id])
        .args(argv)
        .stdin(Stdio::null())
        .output()?;
    Ok(
        json!({"code":output.status.code().unwrap_or(-1),"stdout":String::from_utf8_lossy(&output.stdout),"stderr":String::from_utf8_lossy(&output.stderr)}),
    )
}

/// Stops the sandbox, deletes its namespace and forgets it.
///
/// Teardown is best effort past the existence check: a sandbox that already
/// lost half its pieces should still disappear from the daemon's view.
pub fn remove(daemon: &Daemon, id: String) -> Result<Value> {
    if !valid_id(&id) {
        return Err(error::coded(ErrorCode::InvalidId, "invalid id"));
    }
    let c = &daemon.config;
    let ns = format!("sbx-{id}");
    let _lifecycle = daemon.lifecycle.lock().expect("lifecycle lock poisoned");
    if !net::namespace_exists(&ns) && !exists(c, &id)? {
        return Err(error::coded(
            ErrorCode::NotFound,
            format!("no such sandbox '{id}'"),
        ));
    }
    let _ = command::status(&c.runsc, &["--root", &c.runsc_root, "kill", &id, "KILL"]);
    thread::sleep(Duration::from_secs(1));
    let _ = command::status(&c.runsc, &["--root", &c.runsc_root, "delete", &id]);
    net::delete_namespace(&ns);
    daemon
        .state
        .lock()
        .expect("state lock poisoned")
        .entries
        .retain(|record| record.id != id);
    daemon.persist()?;
    Ok(json!({"id":id,"removed":true}))
}

/// Undoes a failed [`create`] when it is dropped without being disarmed.
struct Rollback<'a> {
    active: bool,
    ns: String,
    daemon: &'a Daemon,
    old_index: u32,
    started_id: Option<String>,
}

impl Drop for Rollback<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(id) = &self.started_id {
            let c = &self.daemon.config;
            let _ = command::status(&c.runsc, &["--root", &c.runsc_root, "kill", id, "KILL"]);
            let _ = command::status(&c.runsc, &["--root", &c.runsc_root, "delete", id]);
        }
        net::delete_namespace(&self.ns);
        if let Ok(mut state) = self.daemon.state.lock() {
            state.next_index = self.old_index;
            if let Some(id) = &self.started_id {
                state.entries.retain(|record| record.id != *id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_validation() {
        assert!(valid_id("a-1"));
        assert!(valid_id("z"));
        assert!(!valid_id("A"));
        assert!(!valid_id("-a"));
        assert!(!valid_id("a_1"));
        assert!(!valid_id(&"a".repeat(32)));
    }

    #[test]
    fn index_derivation() {
        assert_eq!(
            net::derive_indices(
                "3: v-alpha    inet 10.30.0.2/31 scope global v-alpha\n9: eth0 inet 10.30.0.99/24"
            )
            .into_iter()
            .max()
            .unwrap_or(0),
            1
        );
        assert_eq!(
            net::derive_indices("3: v-a inet 10.30.0.8/31\n4: v-b inet 10.30.0.13/31"),
            vec![4, 6]
        );
    }
}
