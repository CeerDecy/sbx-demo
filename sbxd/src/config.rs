//! Daemon configuration and command-line parsing.

use anyhow::{Result, anyhow};
use sbx_proto::DEFAULT_SOCKET;
use std::{fs, path::PathBuf};

/// Every path, address and mode the daemon works with.
///
/// Plain data: the defaults describe this host's layout, and each flag
/// overrides one field.
#[derive(Clone, Debug)]
pub struct Config {
    /// Unix socket clients connect to.
    pub socket: PathBuf,
    /// runsc binary.
    pub runsc: String,
    /// runsc's private root directory.
    pub runsc_root: String,
    /// Directory holding the private per-sandbox bundles.
    pub bundles: PathBuf,
    /// Bundle used when a request does not name one.
    pub default_bundle: PathBuf,
    /// Persisted daemon state.
    pub state: PathBuf,
    /// The address every sandbox eth0 carries.
    pub ident: String,
    /// Whether runsc starts with nvproxy.
    pub gpu: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            socket: PathBuf::from(DEFAULT_SOCKET),
            runsc: "/opt/gvisor/runsc".into(),
            runsc_root: "/var/run/runsc-gpu".into(),
            bundles: "/opt/gvisor/bundles".into(),
            default_bundle: "/opt/gvisor/bundles/alpine".into(),
            state: "/var/lib/sbxd/state.json".into(),
            ident: "169.254.0.21".into(),
            gpu: nvidia_device_ready(),
        }
    }
}

/// Parses the daemon's flags. An unknown flag is fatal: a typo must not
/// silently start the daemon with defaults.
pub fn parse_args() -> Result<Config> {
    let mut config = Config::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--gpu" {
            config.gpu = true;
            continue;
        }
        if arg == "--no-gpu" {
            config.gpu = false;
            continue;
        }
        let value = args
            .next()
            .ok_or_else(|| anyhow!("missing value for {arg}"))?;
        match arg.as_str() {
            "--socket" => config.socket = value.into(),
            "--runsc" => config.runsc = value,
            "--runsc-root" => config.runsc_root = value,
            "--bundles" => config.bundles = value.into(),
            "--default-bundle" => config.default_bundle = value.into(),
            "--state" => config.state = value.into(),
            "--ident" => config.ident = value,
            _ => return Err(anyhow!("unknown flag {arg}")),
        }
    }
    if config.gpu && !nvidia_device_ready() {
        return Err(anyhow!(
            "--gpu requested but the NVIDIA driver is not usable (/dev/nvidiactl does not open)"
        ));
    }
    Ok(config)
}

/// nvproxy refuses to start unless it can open the host NVIDIA control
/// device. Passing it on a machine without a loaded driver makes every
/// sandbox fail, GPU or not.
///
/// `exists()` is not enough: a stale device node left by a previously
/// installed driver passes the check and then fails at open(2) with ENXIO.
/// Probe by actually opening the control device.
fn nvidia_device_ready() -> bool {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/nvidiactl")
        .is_ok()
}
