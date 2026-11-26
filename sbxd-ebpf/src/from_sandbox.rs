//! Entry point for frames coming from a sandbox.
//!
//! Attached to the TC ingress hook of every sandbox veth (`v-<id>`), before
//! the ARP responder. IPv4 TCP and UDP frames are source-NATed here: the link
//! header is aimed at the host's next hop, the source address and port become
//! the host's egress address and a port from `SNAT_IPLIST`, the checksums are
//! fixed up, the session that brings the reply back is recorded, and the frame
//! is redirected straight out the egress interface.
//!
//! Everything that is not a translated flow — ARP, IPv6, ICMP — passes on to
//! the next classifier. A TCP segment that does not belong to a known session
//! and is not opening one is dropped, so stray segments cannot mint sessions.
//!
//! The report into `FRAMES` is the debug view of the frame *after* this
//! program has had it: for a redirected frame that is exactly what leaves the
//! host, and frames the program leaves alone are unchanged by it.

use crate::{
    consts::{
        ETH_HDR_LEN, ETH_P_ARP, ETH_P_IPV4, ICMP_ECHO_REQUEST, IPPROTO_ICMP, IPPROTO_TCP,
        IPV4_HDR_LEN, SANDBOX_MAC, TCP_SYN,
    },
    egress::{EGRESS_IFINDEX, EGRESS_MAC},
    flow, next_hop::NEXT_HOP_MAC,
    session::{
        self, EGRESS_SESSION, EgressSessionKey, EgressSessionValue, INGRESS_SESSION,
        IngressSessionValue, SessionKey,
    },
    skb,
    snat::{SNAT_IPLIST, SNAT_PORT_END, SNAT_PORT_FIRST},
};
use aya_ebpf::{
    EbpfContext,
    bindings::{TC_ACT_REDIRECT, TC_ACT_SHOT, TC_ACT_UNSPEC, __sk_buff},
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};
use aya_ebpf_bindings::helpers::{bpf_ktime_get_ns, bpf_redirect};
use core::mem::size_of;

/// Length of an Ethernet ARP message for IPv4 over Ethernet (RFC 826).
const ARP_LEN: usize = 28;

/// What the classifier does with a frame.
enum Verdict {
    /// Translated: send it out the egress interface.
    Redirect,
    /// Not this program's business: hand it to the next classifier.
    Pass,
    /// Belongs to no live session and cannot open one.
    Drop,
}

/// Description of one frame, copied to userspace.
///
/// `sbxd/src/ebpf.rs` decodes this exact layout; both sides are `repr(C)` and
/// assert its size.
#[repr(C)]
pub struct FrameEvent {
    /// `bpf_ktime_get_ns` at the time the frame was reported.
    pub timestamp_ns: u64,
    pub ifindex: u32,
    /// Frame length as the hook sees it, link header included.
    pub len: u32,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub ethertype: u16,
    pub ip_proto: u8,
    pub tcp_flags: u8,
    pub arp_op: u8,
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
}

const _: () = assert!(size_of::<FrameEvent>() == 48);

/// Frame reports for the daemon; 256 KiB absorbs bursts without blocking.
#[map]
static FRAMES: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[classifier]
pub fn sbxd_from_sandbox(ctx: TcContext) -> i32 {
    let verdict = translate(&ctx);
    // Reported after translation, so a redirected frame's line carries the
    // headers it actually leaves with.
    emit(&ctx);
    match verdict {
        Verdict::Redirect => {
            // SAFETY: helper call on the frame this program was invoked for,
            // with an ifindex the daemon resolved before the program was
            // loaded.
            let action = unsafe { bpf_redirect(EGRESS_IFINDEX.load(), 0) };
            if action as i32 == TC_ACT_REDIRECT as i32 {
                TC_ACT_REDIRECT as i32
            } else {
                TC_ACT_SHOT as i32
            }
        }
        // Not `TC_ACT_OK`: an accept verdict ends the classifier chain on this
        // hook, which would hide the frame from the ARP responder behind it.
        // `TC_ACT_UNSPEC` passes it on.
        Verdict::Pass => TC_ACT_UNSPEC,
        Verdict::Drop => TC_ACT_SHOT as i32,
    }
}

/// Source-NATs one frame from a sandbox and records the session that will
/// bring the reply back.
fn translate(ctx: &TcContext) -> Verdict {
    let Some(flow) = flow::ipv4_flow(ctx) else {
        return Verdict::Pass;
    };
    // An echo request is ours to translate; an echo reply or an ICMP error
    // from a sandbox has nothing to open a session for.
    if flow.protocol == IPPROTO_ICMP && flow.icmp_type != ICMP_ECHO_REQUEST {
        return Verdict::Pass;
    }
    // SAFETY: `ctx` is the `__sk_buff` the kernel handed to this program.
    let veth_ifindex = unsafe { (*(ctx.as_ptr() as *const __sk_buff)).ifindex };
    // The egress address is a constant of the SNAT entry; reading it leaves
    // the port counter alone.
    // SAFETY: index 0 exists for the life of the map.
    let Some(egress_ip) = (unsafe { SNAT_IPLIST.get_ptr(0) }).map(|entry| unsafe { (*entry).ip })
    else {
        return Verdict::Drop;
    };

    // A flow that was translated before keeps the port it was given; only a
    // new flow takes one from the counter. The key includes the veth because
    // all sandboxes share one address and one MAC.
    let egress_key = EgressSessionKey {
        veth_ifindex,
        flow: SessionKey {
            src_ip: flow.src_ip,
            src_port: flow.src_port,
            dst_ip: flow.dst_ip,
            dst_port: flow.dst_port,
            protocol: flow.protocol,
            _pad: 0,
        },
        _pad: 0,
    };
    // SAFETY: the map is `BPF_F_NO_PREALLOC` and entries are only removed by
    // the daemon's expiry sweep, which never reuses a key while this program
    // holds it, so the reference cannot be aliased by a removal under us.
    let existing = unsafe { EGRESS_SESSION.get(&egress_key) };
    let new_session = existing.is_none();

    // A TCP segment without a session has to be opening one. Anything else is
    // stray — a retransmission after expiry, a scan — and gets no port.
    if new_session && flow.protocol == IPPROTO_TCP && flow.tcp_flags & TCP_SYN == 0 {
        return Verdict::Drop;
    }
    // SAFETY: helper call without preconditions.
    let now = unsafe { bpf_ktime_get_ns() };
    let snat_port = match existing {
        Some(entry) => entry.snat_port,
        None => {
            let Some(port) = allocate_port() else {
                return Verdict::Drop;
            };
            let value = EgressSessionValue {
                access_time: now,
                snat_port: port,
                state: session::initial_state(flow.protocol),
                _pad: [0; 5],
            };
            if EGRESS_SESSION.insert(&egress_key, &value, 0).is_err() {
                // The table is full; the frame cannot be translated.
                return Verdict::Drop;
            }
            port
        }
    };

    // Link header: out through the host's egress device to the next hop.
    if !flow::set_macs(ctx, NEXT_HOP_MAC.load(), EGRESS_MAC.load()) {
        return Verdict::Drop;
    }
    // Network and transport headers: the source address, the source port, and
    // the checksums that cover both.
    if !flow::set_src_ip(ctx, egress_ip)
        || !flow::adjust_csum(
            ctx,
            flow.csum,
            flow.protocol,
            flow.src_ip,
            egress_ip,
            flow.src_port,
            snat_port,
        )
        || ctx.store(flow.src_field(), &snat_port.to_be_bytes(), 0).is_err()
    {
        return Verdict::Drop;
    }

    // The reply comes back as (the sandbox's destination, this egress address
    // and SNAT port), which is the rewritten tuple with source and destination
    // swapped. Keying the session that way means the from-world program looks
    // it up with the returning frame's five tuple as-is.
    let ingress_key = SessionKey {
        src_ip: flow.dst_ip,
        src_port: flow.dst_port,
        dst_ip: egress_ip,
        dst_port: snat_port,
        protocol: flow.protocol,
        _pad: 0,
    };
    // Where the sandbox's segment leaves the connection. The state both
    // halves carry is the same; the egress copy is the one the expiry sweep
    // reads.
    let state = match existing {
        Some(entry) => session::sandbox_packet(entry.state, flow.protocol, flow.tcp_flags),
        None => session::initial_state(flow.protocol),
    };
    if new_session {
        let value = IngressSessionValue {
            access_time: now,
            sbx_mac: SANDBOX_MAC,
            sbx_port: flow.src_port,
            veth_ifindex,
            state,
            _pad: [0; 3],
        };
        // A full table only costs the reply path; the frame is still sent.
        let _ = INGRESS_SESSION.insert(&ingress_key, &value, 0);
        return Verdict::Redirect;
    }

    // Existing session: refresh the timers on both halves and record where
    // the sandbox is in the connection. Nothing is removed here — a closed
    // flow lingers in TIME_WAIT or CLOSE so late segments still translate,
    // and the daemon's sweep takes it out once its time is up.
    // SAFETY: the entry was just found and entries are removed only by the
    // rate-limited sweep, which cannot free it while this program runs.
    if let Some(entry) = unsafe { EGRESS_SESSION.get_ptr_mut(&egress_key) } {
        // SAFETY: as above; the pointer is used only here.
        let entry = unsafe { &mut *entry };
        entry.access_time = now;
        entry.state = state;
    }
    // SAFETY: as above.
    if let Some(entry) = unsafe { INGRESS_SESSION.get_ptr_mut(&ingress_key) } {
        // SAFETY: as above.
        let entry = unsafe { &mut *entry };
        entry.access_time = now;
        entry.state = state;
    }
    Verdict::Redirect
}

/// Takes the next source port from the shared counter.
fn allocate_port() -> Option<u16> {
    // NOTE: this read-modify-write is not atomic. `bpf_spin_lock` on a map
    // value needs BTF describing the value, which this object does not carry;
    // until that lands, two CPUs can hand out the same port.
    // SAFETY: index 0 exists for the life of the map.
    let snat = unsafe { &mut *SNAT_IPLIST.get_ptr_mut(0)? };
    let current = snat.current_port;
    let port = if current + 1 >= SNAT_PORT_END {
        SNAT_PORT_FIRST
    } else {
        current + 1
    };
    snat.current_port = port;
    Some(port)
}

/// Describes the frame and posts it to the ring buffer.
///
/// Debug plumbing: runs on every packet, so it only copies the headers it
/// needs — the Ethernet header, then the IPv4 or ARP header behind it.
fn emit(ctx: &TcContext) -> Option<()> {
    let total = ctx.len() as usize;
    if total < ETH_HDR_LEN {
        return None;
    }
    let mut eth = [0u8; ETH_HDR_LEN];
    if !skb::load(ctx, 0, &mut eth) {
        return None;
    }
    // SAFETY: `ctx` is the `__sk_buff` the kernel handed to this program.
    let ifindex = unsafe { (*(ctx.as_ptr() as *const __sk_buff)).ifindex };
    let mut event = FrameEvent {
        // SAFETY: helper call without preconditions.
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        ifindex,
        len: total as u32,
        src_ip: [0; 4],
        dst_ip: [0; 4],
        src_port: 0,
        dst_port: 0,
        ethertype: u16::from_be_bytes([eth[12], eth[13]]),
        ip_proto: 0,
        tcp_flags: 0,
        arp_op: 0,
        src_mac: [eth[6], eth[7], eth[8], eth[9], eth[10], eth[11]],
        dst_mac: [eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]],
    };
    match event.ethertype {
        ETH_P_IPV4 => describe_ipv4(ctx, total, &mut event),
        ETH_P_ARP => describe_arp(ctx, total, &mut event),
        _ => {}
    }
    let _ = FRAMES.output(&event, 0);
    Some(())
}

/// Fills in the addresses and ports of an IPv4 packet.
fn describe_ipv4(ctx: &TcContext, total: usize, event: &mut FrameEvent) {
    if total < ETH_HDR_LEN + IPV4_HDR_LEN {
        return;
    }
    let mut header = [0u8; IPV4_HDR_LEN];
    if !skb::load(ctx, ETH_HDR_LEN, &mut header) {
        return;
    }
    event.ip_proto = header[9];
    event.src_ip = [header[12], header[13], header[14], header[15]];
    event.dst_ip = [header[16], header[17], header[18], header[19]];
    if header[9] != IPPROTO_TCP && header[9] != crate::consts::IPPROTO_UDP {
        return;
    }
    let ihl = usize::from(header[0] & 0x0f) * 4;
    if ihl < IPV4_HDR_LEN || ETH_HDR_LEN + ihl + 4 > total {
        return;
    }
    let mut ports = [0u8; 4];
    if !skb::load(ctx, ETH_HDR_LEN + ihl, &mut ports) {
        return;
    }
    event.src_port = u16::from_be_bytes([ports[0], ports[1]]);
    event.dst_port = u16::from_be_bytes([ports[2], ports[3]]);
    if header[9] == IPPROTO_TCP {
        // The flags field is the 14th byte of the TCP header.
        let mut flags = [0u8; 1];
        if skb::load(ctx, ETH_HDR_LEN + ihl + 13, &mut flags) {
            event.tcp_flags = flags[0];
        }
    }
}

/// Fills in the operation and protocol addresses of an ARP message.
fn describe_arp(ctx: &TcContext, total: usize, event: &mut FrameEvent) {
    if total < ETH_HDR_LEN + ARP_LEN {
        return;
    }
    let mut message = [0u8; ARP_LEN];
    if !skb::load(ctx, ETH_HDR_LEN, &mut message) {
        return;
    }
    event.arp_op = message[7];
    event.src_ip = [message[14], message[15], message[16], message[17]];
    event.dst_ip = [message[24], message[25], message[26], message[27]];
}
