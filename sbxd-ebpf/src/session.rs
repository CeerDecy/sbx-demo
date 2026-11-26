//! Keys for the session table.
//!
//! A session is one direction of a transport flow. It is identified the same
//! way every NAT does it: by the IPv4 five tuple taken straight from the
//! headers, with no byte swapping, so the key can be built from a frame as it
//! arrives.
//!
//! Each session also records where its connection is. The classifiers move the
//! state with every packet they see — the sandbox's side through the
//! from-sandbox program, the world's through the from-world program — and the
//! daemon expires sessions by it: a handshake that never completes, a close
//! that never finishes and a connection that has been idle all look the same in
//! the tables, and the state tells them apart.

use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC,
    macros::map,
    maps::HashMap,
};
use core::mem::size_of;

use crate::consts::{IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, TCP_FIN, TCP_RST, TCP_SYN};

/// IPv4 five tuple identifying one direction of a flow.
///
/// The session table will be keyed by this; two frames with the same key
/// belong to the same session and share its translation state.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SessionKey {
    /// Source address, as it appears in the IP header.
    pub src_ip: [u8; 4],
    /// Destination address, as it appears in the IP header.
    pub dst_ip: [u8; 4],
    /// Source port, in network byte order.
    pub src_port: u16,
    /// Destination port, in network byte order.
    pub dst_port: u16,
    /// IP protocol number: `IPPROTO_TCP`, `IPPROTO_UDP`, ...
    pub protocol: u8,
    /// Padding, so the key is exactly its fields and has no implicit padding
    /// bytes a userspace mirror would have to guess at.
    pub _pad: u8,
}

const _: () = assert!(size_of::<SessionKey>() == 14);

/// The sandbox has sent its SYN and is waiting for the answer.
pub const TCP_SYN_SENT: u8 = 0;
/// Both SYNs have passed; the sandbox's ACK completes the handshake.
pub const TCP_SYN_RECV: u8 = 1;
/// The connection is open.
pub const TCP_ESTABLISHED: u8 = 2;
/// The world closed first; the sandbox has not sent its FIN yet.
pub const TCP_CLOSE_WAIT: u8 = 3;
/// The sandbox has sent its FIN; `FIN_WAIT_1` and `FIN_WAIT_2` merged.
pub const TCP_FIN_WAIT: u8 = 4;
/// Both directions have closed; only late segments can still arrive.
pub const TCP_TIME_WAIT: u8 = 5;
/// The sandbox answered the world's FIN; waiting for the world's ACK.
pub const TCP_LAST_ACK: u8 = 6;
/// The connection ended — a reset, or a close handshake that finished.
pub const TCP_CLOSE: u8 = 7;
/// A UDP flow whose peer has not answered yet.
pub const UDP_UNREPLIED: u8 = 8;
/// A UDP flow whose peer has answered at least once.
pub const UDP_REPLIED: u8 = 9;
/// An echo request waiting for its reply. There is no further state: the
/// identifier in the reply is all a match needs.
pub const ICMP_PENDING: u8 = 10;

/// State a session starts in.
pub fn initial_state(protocol: u8) -> u8 {
    match protocol {
        IPPROTO_TCP => TCP_SYN_SENT,
        IPPROTO_ICMP => ICMP_PENDING,
        _ => UDP_UNREPLIED,
    }
}

/// The state a packet from the sandbox moves the session to.
pub fn sandbox_packet(state: u8, protocol: u8, tcp_flags: u8) -> u8 {
    if protocol == IPPROTO_TCP {
        sandbox_segment(state, tcp_flags)
    } else {
        state
    }
}

/// The state a packet from the world moves the session to.
///
/// Only TCP, UDP and ICMP echo reach here — the flow parser admits nothing
/// else. A datagram coming back is the reply; an echo reply changes nothing.
pub fn world_packet(state: u8, protocol: u8, tcp_flags: u8) -> u8 {
    match protocol {
        IPPROTO_TCP => world_segment(state, tcp_flags),
        IPPROTO_UDP => UDP_REPLIED,
        _ => state,
    }
}

/// Client-side TCP state after the sandbox sends one segment.
///
/// The sandbox is the only side that opens connections — the datapath only
/// translates flows it has seen a sandbox start — so the state is the client's,
/// which is what the close transitions below assume.
fn sandbox_segment(state: u8, tcp_flags: u8) -> u8 {
    if tcp_flags & TCP_RST != 0 {
        return TCP_CLOSE;
    }
    if tcp_flags & TCP_SYN != 0 {
        // A retransmitted SYN leaves a handshake where it was; a SYN on a
        // session that had already progressed starts a new connection on the
        // same tuple.
        return match state {
            TCP_SYN_SENT | TCP_SYN_RECV => state,
            _ => TCP_SYN_SENT,
        };
    }
    if tcp_flags & TCP_FIN != 0 {
        return match state {
            // The world closed first, so this FIN starts the sandbox's own.
            TCP_CLOSE_WAIT => TCP_LAST_ACK,
            // A retransmitted FIN, or one after the close already progressed.
            TCP_FIN_WAIT | TCP_TIME_WAIT | TCP_LAST_ACK | TCP_CLOSE => state,
            _ => TCP_FIN_WAIT,
        };
    }
    match state {
        TCP_SYN_RECV => TCP_ESTABLISHED,
        other => other,
    }
}

/// Client-side TCP state after the world sends one segment.
fn world_segment(state: u8, tcp_flags: u8) -> u8 {
    if tcp_flags & TCP_RST != 0 {
        return TCP_CLOSE;
    }
    if tcp_flags & TCP_SYN != 0 {
        // The answer to the sandbox's SYN. A SYN in a later state is a
        // retransmission of the same answer, or of a connection the sandbox
        // is about to replace; neither changes where this session is.
        return match state {
            TCP_SYN_SENT => TCP_SYN_RECV,
            other => other,
        };
    }
    if tcp_flags & TCP_FIN != 0 {
        return match state {
            // Both directions have closed.
            TCP_FIN_WAIT => TCP_TIME_WAIT,
            // Retransmissions of a FIN that has already been accounted for.
            TCP_TIME_WAIT | TCP_LAST_ACK | TCP_CLOSE => state,
            // The world closes first; the sandbox has a FIN to send once its
            // application notices.
            _ => TCP_CLOSE_WAIT,
        };
    }
    match state {
        // The ACK that answers the sandbox's FIN in a passive close.
        TCP_LAST_ACK => TCP_CLOSE,
        other => other,
    }
}

/// What an ingress session remembers about its sandbox.
///
/// Frames coming back from the outside carry the host's address and the SNAT
/// port; the session turns those into the sandbox that owns the flow, so the
/// reply can be rewritten to the sandbox's own link address and port.
///
/// The timestamp comes first, and a trailing pad closes the value: a `u64`
/// forces 8-byte alignment, so 20 bytes of fields would otherwise end in four
/// implicit padding bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IngressSessionValue {
    /// Last time a frame was seen for this session, in nanoseconds from
    /// `bpf_ktime_get_ns`. Both classifiers refresh it; the daemon expires
    /// sessions that have been idle for longer than their state allows.
    pub access_time: u64,
    /// Hardware address of the sandbox's eth0, as it appears in the frame.
    pub sbx_mac: [u8; 6],
    /// Port the sandbox sent from, in network byte order; it becomes the
    /// destination port of the returning frame.
    pub sbx_port: u16,
    /// Index of the sandbox's `v-<id>` veth on the host, where the returning
    /// frame is redirected.
    pub veth_ifindex: u32,
    /// Connection state, one of the `TCP_*` or `UDP_*` values above. Kept in
    /// step with the copy in the egress session.
    pub state: u8,
    /// Padding to the alignment the timestamp forces.
    pub _pad: [u8; 3],
}

const _: () = assert!(size_of::<IngressSessionValue>() == 24);

/// What an egress session remembers about the translation it was given.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EgressSessionValue {
    /// Last time a frame of this session was seen in either direction.
    pub access_time: u64,
    /// Source port the flow was translated to, in network byte order.
    pub snat_port: u16,
    /// Connection state, one of the `TCP_*` or `UDP_*` values above. This is
    /// the copy the daemon's expiry sweep reads.
    pub state: u8,
    /// Padding to the alignment the timestamp forces.
    pub _pad: [u8; 5],
}

const _: () = assert!(size_of::<EgressSessionValue>() == 16);

/// Key of the egress table: the sandbox's own five tuple plus the veth it
/// arrived on.
///
/// The five tuple alone does not identify a flow here: every sandbox shares
/// one address and one MAC, so two sandboxes can send from the same port to
/// the same destination at the same time. The veth index keeps their sessions
/// apart.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EgressSessionKey {
    /// Index of the `v-<id>` veth the frame arrived on.
    pub veth_ifindex: u32,
    /// The flow as the sandbox sent it: `src` is the sandbox, `dst` the peer.
    pub flow: SessionKey,
    /// Padding to the alignment the index forces.
    pub _pad: u16,
}

const _: () = assert!(size_of::<EgressSessionKey>() == 20);

/// Live ingress sessions, keyed by five tuple.
///
/// One entry per flow the datapath is translating back into a sandbox. A
/// sandbox host keeps far more than the default handful of flows alive, so the
/// ceiling is a million sessions; `BPF_F_NO_PREALLOC` makes the kernel
/// allocate entries as flows appear instead of charging that ceiling up front.
/// The limit is still a hard cap — inserts fail once it is reached, and the
/// daemon's expiry sweep removes entries that outlive their connection state.
#[map]
pub static INGRESS_SESSION: HashMap<SessionKey, IngressSessionValue> =
    HashMap::with_max_entries(1 << 20, BPF_F_NO_PREALLOC as u32);

/// Live egress sessions, keyed by the sandbox's own five tuple.
///
/// Before a frame is translated the datapath looks it up here and reuses the
/// source port it was already given; without this table every packet of one
/// connection would leave with a fresh port and the far side would treat each
/// one as a different connection.
#[map]
pub static EGRESS_SESSION: HashMap<EgressSessionKey, EgressSessionValue> =
    HashMap::with_max_entries(1 << 20, BPF_F_NO_PREALLOC as u32);
