//! Answers ARP requests for the gateway address.
//!
//! Attached to the TC ingress hook of every sandbox veth (`v-<id>`). A sandbox
//! has only a default route through `169.254.0.1`, so the first frame it ever
//! sends is an ARP broadcast for that address. This program rewrites the
//! request into a reply carrying the MAC of the host-side `sbx0` device and
//! sends it back out the same veth, which delivers it to the sandbox's eth0.
//! Everything that is not such a request passes through untouched.

use crate::{
    consts::{ETH_HDR_LEN, ETH_P_ARP, ETH_P_IPV4},
    skb,
};
use aya_ebpf::{
    EbpfContext,
    bindings::{TC_ACT_OK, TC_ACT_REDIRECT, TC_ACT_SHOT, __sk_buff},
    macros::classifier,
    programs::TcContext,
};
use aya_ebpf_bindings::helpers::bpf_redirect;

/// Address every sandbox routes through.
const GATEWAY_IP: [u8; 4] = [169, 254, 0, 1];
/// MAC of the host-side `sbx0` device; the sandbox sees it as the gateway's.
const GATEWAY_MAC: [u8; 6] = [0x02, 0x53, 0x42, 0x58, 0x00, 0x01];

const ARP_LEN: usize = 28;
const ARPHRD_ETHER: u16 = 1;
const ARP_OP_REQUEST: u16 = 1;
const ARP_OP_REPLY: u16 = 2;

#[classifier]
pub fn sbxd_arp(ctx: TcContext) -> i32 {
    match reply(&ctx) {
        Some(action) => action,
        None => TC_ACT_OK as i32,
    }
}

/// Rewrites and redirects the frame when it is an ARP request for the gateway.
fn reply(ctx: &TcContext) -> Option<i32> {
    const FRAME_LEN: usize = ETH_HDR_LEN + ARP_LEN;
    if ctx.len() < FRAME_LEN as u32 {
        return None;
    }
    let mut frame = [0u8; FRAME_LEN];
    if !skb::load(ctx, 0, &mut frame) {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ETH_P_ARP {
        return None;
    }
    let arp = &frame[ETH_HDR_LEN..];
    if u16::from_be_bytes([arp[0], arp[1]]) != ARPHRD_ETHER
        || u16::from_be_bytes([arp[2], arp[3]]) != ETH_P_IPV4
        || arp[4] != 6
        || arp[5] != 4
        || u16::from_be_bytes([arp[6], arp[7]]) != ARP_OP_REQUEST
        || arp[24] != GATEWAY_IP[0]
        || arp[25] != GATEWAY_IP[1]
        || arp[26] != GATEWAY_IP[2]
        || arp[27] != GATEWAY_IP[3]
    {
        return None;
    }
    // Turn the request into a reply: the gateway becomes the sender and the
    // requester the target.
    let requester_mac = [arp[8], arp[9], arp[10], arp[11], arp[12], arp[13]];
    let requester_ip = [arp[14], arp[15], arp[16], arp[17]];
    frame[0..6].copy_from_slice(&requester_mac);
    frame[6..12].copy_from_slice(&GATEWAY_MAC);
    let arp = &mut frame[ETH_HDR_LEN..];
    arp[6..8].copy_from_slice(&ARP_OP_REPLY.to_be_bytes());
    arp[8..14].copy_from_slice(&GATEWAY_MAC);
    arp[14..18].copy_from_slice(&GATEWAY_IP);
    arp[18..24].copy_from_slice(&requester_mac);
    arp[24..28].copy_from_slice(&requester_ip);
    if ctx.store(0, &frame, 0).is_err() {
        return Some(TC_ACT_SHOT as i32);
    }
    // SAFETY: `ctx` is the `__sk_buff` the kernel handed to this program.
    let ifindex = unsafe { (*(ctx.as_ptr() as *const __sk_buff)).ifindex };
    // SAFETY: helper call on a valid skb and a valid ifindex; it retargets the
    // skb for transmission, which the return value below consumes.
    let action = unsafe { bpf_redirect(ifindex, 0) };
    if action as i32 == TC_ACT_REDIRECT as i32 {
        Some(TC_ACT_REDIRECT as i32)
    } else {
        Some(TC_ACT_SHOT as i32)
    }
}
