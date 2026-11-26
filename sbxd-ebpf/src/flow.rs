//! Parsing and rewriting of the IPv4 flow headers, shared by both classifiers.
//!
//! Only IPv4 without options carrying TCP, UDP or an ICMP echo is handled: the
//! checksum and offset arithmetic below assumes the 20-byte header. Everything
//! else is left to the rest of the path.
//!
//! ICMP has no ports. Echo messages do carry a 16-bit identifier that the peer
//! copies into its reply, so it is treated as the port this datapath's session
//! tables key on: an echo request's identifier sits where a flow's source port
//! would, a reply's where the destination port would.

use crate::{
    consts::{
        ETH_HDR_LEN, ETH_P_IPV4, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST, IPV4_HDR_LEN, IPPROTO_ICMP,
        IPPROTO_TCP, IPPROTO_UDP,
    },
    csum, skb,
};
use aya_ebpf::programs::TcContext;

/// Two 16-bit ports.
const PORTS_LEN: usize = 4;
/// Smallest TCP header; its checksum sits 16 bytes in.
const TCP_HDR_LEN: usize = 20;
const TCP_CSUM_OFFSET: usize = 16;
/// UDP header, with its checksum 6 bytes in.
const UDP_HDR_LEN: usize = 8;
const UDP_CSUM_OFFSET: usize = 6;
/// An echo message's header: type, code, checksum, identifier, sequence. The
/// identifier starts 4 bytes in.
const ICMP_LEN: usize = 8;
const ICMP_CSUM_OFFSET: usize = 2;
const ICMP_ID_OFFSET: usize = 4;

/// The parts of a frame both classifiers look at.
pub struct Flow {
    pub protocol: u8,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    /// Source port, in network byte order; an echo request's identifier takes
    /// its place.
    pub src_port: u16,
    /// Destination port, in network byte order; an echo reply's identifier
    /// takes its place.
    pub dst_port: u16,
    /// TCP flags byte; zero for UDP and ICMP.
    pub tcp_flags: u8,
    /// ICMP type; zero for TCP and UDP.
    pub icmp_type: u8,
    /// Offset of the transport header.
    pub l4: usize,
    /// Offset of the transport checksum field.
    pub csum: usize,
}

impl Flow {
    /// Offset of the field that carries the sandbox's identity in the
    /// translated frame: the source port, or an echo request's identifier.
    #[inline(always)]
    pub fn src_field(&self) -> usize {
        if self.protocol == IPPROTO_ICMP {
            self.l4 + ICMP_ID_OFFSET
        } else {
            self.l4
        }
    }

    /// Offset of the field that carries the far side's identity: the
    /// destination port, or an echo reply's identifier.
    #[inline(always)]
    pub fn dst_field(&self) -> usize {
        if self.protocol == IPPROTO_ICMP {
            self.l4 + ICMP_ID_OFFSET
        } else {
            self.l4 + 2
        }
    }
}

/// Reads the headers of an IPv4 TCP, UDP or ICMP echo frame.
///
/// Returns `None` for anything else — ARP, IPv6, other ICMP messages, options
/// in the header, VLAN tags — which the callers pass along untouched.
#[inline(always)]
pub fn ipv4_flow(ctx: &TcContext) -> Option<Flow> {
    let total = ctx.len() as usize;
    if total < ETH_HDR_LEN + IPV4_HDR_LEN {
        return None;
    }
    let mut eth = [0u8; ETH_HDR_LEN];
    if !skb::load(ctx, 0, &mut eth) || u16::from_be_bytes([eth[12], eth[13]]) != ETH_P_IPV4 {
        return None;
    }
    let mut ip = [0u8; IPV4_HDR_LEN];
    if !skb::load(ctx, ETH_HDR_LEN, &mut ip) || ip[0] != 0x45 {
        return None;
    }
    let protocol = ip[9];
    let (transport_len, csum_offset) = match protocol {
        IPPROTO_TCP => (TCP_HDR_LEN, TCP_CSUM_OFFSET),
        IPPROTO_UDP => (UDP_HDR_LEN, UDP_CSUM_OFFSET),
        IPPROTO_ICMP => (ICMP_LEN, ICMP_CSUM_OFFSET),
        _ => return None,
    };
    let l4 = ETH_HDR_LEN + IPV4_HDR_LEN;
    if total < l4 + transport_len {
        return None;
    }
    // The first four bytes after the IP header: both ports, or type, code and
    // checksum for ICMP.
    let mut head = [0u8; PORTS_LEN];
    if !skb::load(ctx, l4, &mut head) {
        return None;
    }
    let mut tcp_flags = 0;
    let mut icmp_type = 0;
    let (src_port, dst_port) = match protocol {
        IPPROTO_TCP => {
            // The flags field is the 14th byte of the TCP header.
            let mut flags = [0u8; 1];
            if skb::load(ctx, l4 + 13, &mut flags) {
                tcp_flags = flags[0];
            }
            (
                u16::from_be_bytes([head[0], head[1]]),
                u16::from_be_bytes([head[2], head[3]]),
            )
        }
        IPPROTO_UDP => (
            u16::from_be_bytes([head[0], head[1]]),
            u16::from_be_bytes([head[2], head[3]]),
        ),
        _ => {
            // Only echo messages carry an identifier this datapath can
            // translate; errors refer to a flow they embed and pass by.
            icmp_type = head[0];
            if icmp_type != ICMP_ECHO_REQUEST && icmp_type != ICMP_ECHO_REPLY {
                return None;
            }
            let mut id = [0u8; 2];
            if !skb::load(ctx, l4 + ICMP_ID_OFFSET, &mut id) {
                return None;
            }
            let id = u16::from_be_bytes(id);
            // The identity of the flow is the sandbox's, so it is placed on
            // whichever side of the key the sandbox is on.
            if icmp_type == ICMP_ECHO_REQUEST {
                (id, 0)
            } else {
                (0, id)
            }
        }
    };
    Some(Flow {
        protocol,
        src_ip: [ip[12], ip[13], ip[14], ip[15]],
        dst_ip: [ip[16], ip[17], ip[18], ip[19]],
        src_port,
        dst_port,
        tcp_flags,
        icmp_type,
        l4,
        csum: l4 + csum_offset,
    })
}

/// Replaces both link-layer addresses of the frame.
#[inline(always)]
pub fn set_macs(ctx: &TcContext, dst: [u8; 6], src: [u8; 6]) -> bool {
    let mut eth = [0u8; ETH_HDR_LEN];
    if !skb::load(ctx, 0, &mut eth) {
        return false;
    }
    eth[0..6].copy_from_slice(&dst);
    eth[6..12].copy_from_slice(&src);
    ctx.store(0, &eth, 0).is_ok()
}

/// Puts `address` in the header's source address and refreshes its checksum.
#[inline(always)]
pub fn set_src_ip(ctx: &TcContext, address: [u8; 4]) -> bool {
    set_ip(ctx, 12, address)
}

/// Puts `address` in the header's destination address and refreshes its
/// checksum.
#[inline(always)]
pub fn set_dst_ip(ctx: &TcContext, address: [u8; 4]) -> bool {
    set_ip(ctx, 16, address)
}

#[inline(always)]
fn set_ip(ctx: &TcContext, field: usize, address: [u8; 4]) -> bool {
    let mut ip = [0u8; IPV4_HDR_LEN];
    if !skb::load(ctx, ETH_HDR_LEN, &mut ip) {
        return false;
    }
    ip[field..field + 4].copy_from_slice(&address);
    // The checksum field itself must read as zero while the sum is computed.
    ip[10..12].copy_from_slice(&[0, 0]);
    let header_csum = csum::checksum(&ip);
    ip[10..12].copy_from_slice(&header_csum.to_be_bytes());
    ctx.store(ETH_HDR_LEN, &ip, 0).is_ok()
}

/// Adjusts the transport checksum for an address and port that changed.
///
/// The TCP and UDP checksums cover a pseudo header of both addresses, and the
/// payload underneath, which the datapath never reads, so those are corrected
/// incrementally. The ICMP checksum covers the message alone — there is no
/// pseudo header — so only its identifier is replaced.
///
/// Every argument is a scalar: a struct passed by reference would have to be
/// copied onto the BPF stack, which the verifier keeps within 512 bytes.
#[inline(always)]
pub fn adjust_csum(
    ctx: &TcContext,
    csum_offset: usize,
    protocol: u8,
    old_addr: [u8; 4],
    new_addr: [u8; 4],
    old_port: u16,
    new_port: u16,
) -> bool {
    let mut bytes = [0u8; 2];
    if !skb::load(ctx, csum_offset, &mut bytes) {
        return false;
    }
    let old_csum = u16::from_be_bytes(bytes);
    // Zero means the sender computed no checksum at all (allowed for UDP);
    // leave it that way.
    if protocol == IPPROTO_UDP && old_csum == 0 {
        return true;
    }
    let mut new_csum = if protocol == IPPROTO_ICMP {
        old_csum
    } else {
        let csum = csum::replace(
            old_csum,
            u16::from_be_bytes([old_addr[0], old_addr[1]]),
            u16::from_be_bytes([new_addr[0], new_addr[1]]),
        );
        csum::replace(
            csum,
            u16::from_be_bytes([old_addr[2], old_addr[3]]),
            u16::from_be_bytes([new_addr[2], new_addr[3]]),
        )
    };
    new_csum = csum::replace(new_csum, old_port, new_port);
    // A UDP checksum that computes to zero is transmitted as all ones, so it
    // cannot be mistaken for "not computed".
    if protocol == IPPROTO_UDP && new_csum == 0 {
        new_csum = 0xffff;
    }
    ctx.store(csum_offset, &new_csum.to_be_bytes(), 0).is_ok()
}
