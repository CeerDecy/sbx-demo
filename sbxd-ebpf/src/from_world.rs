//! Entry point for frames coming back to the host from outside.
//!
//! Attached to the TC ingress hook of the egress interface, this is the mirror
//! of [`crate::from_sandbox`]: a frame whose five tuple matches a live ingress
//! session is the reply to a sandbox's flow, so it is rewritten back into the
//! sandbox's own addressing — link header from the `sbx0` gateway to the
//! sandbox, destination address and port restored — and redirected out the
//! sandbox's veth. Everything else, which is most of the host's traffic, is
//! passed on untouched to the host stack.
//!
//! Both halves of the session get their timers refreshed here, and the TCP
//! state moves with the segment just as it does on the egress side.

use crate::{
    consts::{GATEWAY_MAC, ICMP_ECHO_REPLY, IPPROTO_ICMP},
    egress::SANDBOX_IP,
    flow,
    session::{self, EGRESS_SESSION, EgressSessionKey, INGRESS_SESSION, SessionKey},
};
use aya_ebpf::{
    bindings::{TC_ACT_REDIRECT, TC_ACT_SHOT, TC_ACT_UNSPEC},
    macros::classifier,
    programs::TcContext,
};
use aya_ebpf_bindings::helpers::{bpf_ktime_get_ns, bpf_redirect};

#[classifier]
pub fn sbxd_from_world(ctx: TcContext) -> i32 {
    let Some(ifindex) = translate(&ctx) else {
        return TC_ACT_UNSPEC;
    };
    // SAFETY: helper call on the frame this program was invoked for, with the
    // veth index recorded when the session was created.
    let action = unsafe { bpf_redirect(ifindex, 0) };
    if action as i32 == TC_ACT_REDIRECT as i32 {
        TC_ACT_REDIRECT as i32
    } else {
        TC_ACT_SHOT as i32
    }
}

/// Rewrites one returning frame into the sandbox's addressing and returns the
/// veth to redirect it out of, or `None` when the frame is not ours.
fn translate(ctx: &TcContext) -> Option<u32> {
    let flow = flow::ipv4_flow(ctx)?;
    // Only an echo reply is a session's answer. A request from outside is
    // aimed at the host and belongs to the host stack.
    if flow.protocol == IPPROTO_ICMP && flow.icmp_type != ICMP_ECHO_REPLY {
        return None;
    }
    let key = SessionKey {
        src_ip: flow.src_ip,
        src_port: flow.src_port,
        dst_ip: flow.dst_ip,
        dst_port: flow.dst_port,
        protocol: flow.protocol,
        _pad: 0,
    };
    // SAFETY: the map is `BPF_F_NO_PREALLOC` and entries are only removed by
    // the daemon's expiry sweep, which cannot free one while this program
    // holds it.
    let entry = INGRESS_SESSION.get_ptr_mut(&key)?;
    // Everything the rewrite needs is copied out before the pointer could go
    // stale across a helper call.
    // SAFETY: the pointer was just looked up; the entry lives until the sweep
    // removes it.
    let (veth_ifindex, sbx_mac, sbx_port, previous) = unsafe {
        let entry = &*entry;
        (
            entry.veth_ifindex,
            entry.sbx_mac,
            entry.sbx_port,
            entry.state,
        )
    };
    let sandbox_ip = SANDBOX_IP.load();

    // Link header: back to the sandbox, as if it came from its gateway.
    if !flow::set_macs(ctx, sbx_mac, GATEWAY_MAC) {
        return None;
    }
    // The sandbox's address and port, with both checksums fixed up.
    if !flow::set_dst_ip(ctx, sandbox_ip)
        || !flow::adjust_csum(
            ctx,
            flow.csum,
            flow.protocol,
            flow.dst_ip,
            sandbox_ip,
            flow.dst_port,
            sbx_port,
        )
        || ctx.store(flow.dst_field(), &sbx_port.to_be_bytes(), 0).is_err()
    {
        return None;
    }

    // The egress key is the reverse of this one, with the sandbox's own
    // address and port where the world's were.
    let egress_key = EgressSessionKey {
        veth_ifindex,
        flow: SessionKey {
            src_ip: sandbox_ip,
            src_port: sbx_port,
            dst_ip: flow.src_ip,
            dst_port: flow.src_port,
            protocol: flow.protocol,
            _pad: 0,
        },
        _pad: 0,
    };
    // Timers and connection state: the segment reached both halves of the
    // session, and only the egress copy is read by the expiry sweep.
    // SAFETY: helper call without preconditions.
    let now = unsafe { bpf_ktime_get_ns() };
    let state = session::world_packet(previous, flow.protocol, flow.tcp_flags);
    // SAFETY: as at the top; the entry lives until the sweep removes it.
    if let Some(entry) = EGRESS_SESSION.get_ptr_mut(&egress_key) {
        // SAFETY: as above; the pointer is used only here.
        let entry = unsafe { &mut *entry };
        entry.access_time = now;
        entry.state = state;
    }
    // SAFETY: as above.
    if let Some(entry) = INGRESS_SESSION.get_ptr_mut(&key) {
        // SAFETY: as above.
        let entry = unsafe { &mut *entry };
        entry.access_time = now;
        entry.state = state;
    }
    Some(veth_ifindex)
}
