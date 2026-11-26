//! Kernel side of the sandbox datapath.
//!
//! Two classifiers are attached to the TC ingress hook of every sandbox veth
//! (`v-<id>`), in this order:
//!
//! * [`from_sandbox::sbxd_from_sandbox`] handles traffic leaving a sandbox —
//!   it leaves frames alone for now and only copies their headers into a ring
//!   buffer that the daemon drains into its log;
//! * [`arp::sbxd_arp`] answers the sandbox's ARP request for the gateway,
//!   rewriting the frame into a reply and redirecting it back out the veth.
//!
//! The order matters: classifiers on one hook run in attach order, and the
//! responder redirects the frames it handles, so a program attached after it
//! would never see them.

#![no_std]
#![no_main]

mod arp;
mod consts;
mod csum;
mod egress;
mod flow;
mod from_sandbox;
mod from_world;
mod next_hop;
mod session;
mod skb;
mod snat;

/// The verifier rejects any program path that can actually panic; the handler
/// only has to exist so the crate links.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: unreachable by construction — see above.
    unsafe { core::hint::unreachable_unchecked() }
}
