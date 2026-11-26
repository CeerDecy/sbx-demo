//! Source-NAT state for traffic leaving a sandbox.
//!
//! All sandboxes share one presence on the host network, so a frame that
//! leaves a sandbox is rewritten to carry the host's egress address and a
//! source port assigned from this table. The daemon writes the address and the
//! first port while the object loads, before anything is attached; the
//! datapath advances `current_port` as it hands ports out.
//!
//! Note: once the datapath assigns ports, every read and write of this entry
//! is shared mutable state and must happen inside a `bpf_spin_lock` on the map
//! value. The lock field is not part of the entry yet — it goes in as the
//! first field when port assignment lands. The loader's initial write needs no
//! lock: it happens before any program is attached.

use aya_ebpf::{macros::map, maps::Array};
use core::mem::size_of;

/// One source-NAT entry: the address frames leave with and the next port to
/// assign.
#[repr(C)]
pub struct SnatEntry {
    /// IPv4 address of the host's egress interface.
    pub ip: [u8; 4],
    /// Next source port to assign, in host byte order.
    pub current_port: u16,
}

const _: () = assert!(size_of::<SnatEntry>() == 6);

/// First source port handed out; the counter wraps at [`SNAT_PORT_END`].
pub const SNAT_PORT_FIRST: u16 = 30_000;
/// One past the last source port handed out.
pub const SNAT_PORT_END: u16 = 60_000;

/// A single entry is all there is: one egress interface, one address, and one
/// port counter shared by every sandbox.
#[map]
pub static SNAT_IPLIST: Array<SnatEntry> = Array::with_max_entries(1, 0);
