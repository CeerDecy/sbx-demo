//! Constants the daemon bakes into the datapath at load time.
//!
//! The daemon resolves them once at startup and overrides these globals before
//! the object is loaded, so the programs read plain constants:
//!
//! * [`EGRESS_MAC`] — the egress interface's own hardware address, a frame
//!   forwarded out of the host must carry it at the link layer;
//! * [`EGRESS_IFINDEX`] — the egress interface, where translated frames are
//!   redirected;
//! * [`SANDBOX_IP`] — the address every sandbox carries.
//!
//! Their zero values mean "not set" and are never usable, so a datapath built
//! without the loader's overrides is broken by construction.

use aya_ebpf::Global;

#[unsafe(no_mangle)]
pub static EGRESS_MAC: Global<[u8; 6]> = Global::new([0; 6]);

/// Index of the egress interface. A translated frame is redirected straight
/// out it, so the kernel's own routing never sees the sandbox's traffic.
#[unsafe(no_mangle)]
pub static EGRESS_IFINDEX: Global<u32> = Global::new(0);

/// Address of every sandbox's eth0; a frame returning to the host is
/// addressed to it.
#[unsafe(no_mangle)]
pub static SANDBOX_IP: Global<[u8; 4]> = Global::new([0; 4]);
