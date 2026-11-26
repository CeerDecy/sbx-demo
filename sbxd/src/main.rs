//! Runs gVisor sandboxes on behalf of `sbx-cli`.
//!
//! The daemon owns everything privileged: network namespaces, the per-sandbox
//! veth pair, runsc's root directory and the pty relay behind `attach`. The
//! client only parses arguments and speaks the socket protocol.

mod attach;
mod bundle;
mod command;
mod config;
mod daemon;
mod ebpf;
mod error;
mod files;
mod net;
mod sandbox;
mod session;
mod state;

use anyhow::{Result, anyhow};
use daemon::Daemon;
use std::{sync::Arc, thread};

fn main() -> Result<()> {
    let config = config::parse_args()?;
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!("sbxd must run as root"));
    }
    // SAFETY: `umask` only changes the file-creation mask of this process,
    // before any worker threads exist.
    unsafe {
        libc::umask(0o077);
    }
    net::ensure_gateway_link()?;
    // Resolved before the datapath is loaded: the from-sandbox program gets the
    // next hop baked in as a constant, and the source-NAT table is seeded with
    // the egress address.
    let egress = net::egress()?;
    eprintln!(
        "datapath: egress {} {} ({}) via {}",
        egress.interface,
        egress.source,
        net::format_mac(egress.source_mac),
        net::format_mac(egress.next_hop_mac)
    );
    let (mut datapath, frames) = ebpf::Datapath::load(&egress, &config.ident)?;
    thread::spawn(move || frames.run());
    // Sessions expire by their connection state; the sweep needs the maps,
    // which the datapath gives up here.
    let expiry = datapath.expiry(egress.source)?;
    thread::spawn(move || expiry.run());
    let daemon = Daemon::load(config, datapath)?;
    daemon.attach_existing();
    Arc::new(daemon).serve()
}
