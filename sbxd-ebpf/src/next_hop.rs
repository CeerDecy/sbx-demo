//! Hardware address of the host's next hop, baked in at load time.
//!
//! Frames a sandbox sends are rewritten to go to the host's own next hop
//! instead of the gateway MAC the sandbox believes in. The daemon resolves
//! that address once at startup and overrides this global before the object is
//! loaded, so the datapath reads it from a constant rather than looking it up
//! per packet or keeping it in a writable map.
//!
//! The zero value means "not set"; it is never a usable destination, so a
//! datapath built without the loader's override is broken by construction.

use aya_ebpf::Global;

#[unsafe(no_mangle)]
pub static NEXT_HOP_MAC: Global<[u8; 6]> = Global::new([0; 6]);
