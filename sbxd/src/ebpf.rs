//! eBPF datapath loaded into the kernel by the daemon.
//!
//! The object is compiled from `sbxd-ebpf/` by `build.rs` and holds two
//! classifiers, both attached to the ingress hook of every sandbox veth
//! (`v-<id>`): [`FROM_SANDBOX_PROGRAM`] handles traffic leaving the sandbox,
//! [`ARP_PROGRAM`] answers its ARP request for the gateway. The former only
//! copies frame headers into the `FRAMES` ring buffer for now, which the daemon
//! logs through [`FrameLog`]; rewriting a frame is where the datapath grows.
//!
//! TCX links are file-descriptor based, so dropping the [`Datapath`] detaches
//! the programs: the datapath lives exactly as long as the daemon.

use anyhow::{Context, Result, anyhow};
use aya::{
    Ebpf, EbpfLoader, Pod,
    maps::{Array, MapData, RingBuf},
    programs::{SchedClassifier, TcAttachType},
};
use std::{
    ffi::{CStr, CString},
    io,
    mem::size_of,
    net::Ipv4Addr,
    ptr, thread,
    time::{Duration, Instant},
};

use crate::{net, session::SessionExpiry};

/// Compiled eBPF object, produced by the build script.
const OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sbxd-ebpf.o"));

/// Handles traffic leaving a sandbox; attached before the ARP responder.
const FROM_SANDBOX_PROGRAM: &str = "sbxd_from_sandbox";
/// Handles replies coming back from outside; attached to the egress interface.
const FROM_WORLD_PROGRAM: &str = "sbxd_from_world";
/// Answers ARP requests for the gateway.
const ARP_PROGRAM: &str = "sbxd_arp";
/// Ring buffer the from-sandbox program fills.
const FRAMES_MAP: &str = "FRAMES";
/// Constant the from-sandbox program reads the next hop's hardware address
/// from; the loader overrides it before the program is verified.
const NEXT_HOP_MAC: &str = "NEXT_HOP_MAC";
/// Constant the from-sandbox program reads the egress interface's hardware
/// address from, so rewritten frames carry a source the network accepts.
const EGRESS_MAC: &str = "EGRESS_MAC";
/// Constant naming the interface translated frames are redirected out of.
const EGRESS_IFINDEX: &str = "EGRESS_IFINDEX";
/// Constant holding the address every sandbox carries, so replies can be
/// addressed to it.
const SANDBOX_IP: &str = "SANDBOX_IP";
/// Source-NAT table the datapath translates frames with.
const SNAT_IPLIST_MAP: &str = "SNAT_IPLIST";
/// Session table keyed by the reply's five tuple; the expiry sweep empties it.
const INGRESS_SESSION_MAP: &str = "INGRESS_SESSION";
/// Session table keyed by the sandbox's own five tuple; the expiry sweep runs
/// on it and removes from both tables.
const EGRESS_SESSION_MAP: &str = "EGRESS_SESSION";

/// First source port handed out; the datapath advances it from here.
const SNAT_FIRST_PORT: u16 = 30_000;

/// At most this many frame lines per second reach the log; the kernel drops
/// nothing, only the debug log is bounded.
const LOG_BUDGET: u32 = 200;

const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// The loaded object together with the links attaching it to the veths.
pub struct Datapath {
    bpf: Ebpf,
}

impl Datapath {
    /// Loads the object, fills in the state the datapath starts from, verifies
    /// every program into the kernel, and attaches the from-world handler to
    /// the egress interface.
    ///
    /// `egress` is the host's resolvable path to the outside: the next hop's
    /// hardware address becomes a constant of the from-sandbox program, and
    /// the egress address seeds the source-NAT table. Nothing else writes the
    /// table afterwards, so the one write here needs no lock. `sandbox_ip` is
    /// the address every sandbox carries, which replies are rewritten to.
    ///
    /// The returned [`FrameLog`] reads the ring buffer the from-sandbox
    /// program fills; it blocks, so it belongs on a thread of its own.
    pub fn load(egress: &net::Egress, sandbox_ip: &str) -> Result<(Self, FrameLog)> {
        if egress.next_hop_mac == [0; 6] {
            return Err(anyhow!("next hop MAC must be resolved before loading"));
        }
        let sandbox_ip: Ipv4Addr = sandbox_ip
            .parse()
            .with_context(|| format!("sandbox address {sandbox_ip:?} is not one address"))?;
        // Translated frames are redirected straight out this interface, and
        // the from-world handler is attached to it.
        let egress_ifindex = interface_index(&egress.interface)?;
        let mut bpf = EbpfLoader::new()
            .override_global(NEXT_HOP_MAC, &egress.next_hop_mac[..], true)
            .override_global(EGRESS_MAC, &egress.source_mac[..], true)
            .override_global(EGRESS_IFINDEX, &egress_ifindex, true)
            .override_global(SANDBOX_IP, &sandbox_ip.octets()[..], true)
            .load(OBJECT)
            .context("load eBPF object")?;
        let mut snat: Array<&mut MapData, SnatEntry> = bpf
            .map_mut(SNAT_IPLIST_MAP)
            .ok_or_else(|| anyhow!("eBPF map {SNAT_IPLIST_MAP} is missing"))?
            .try_into()
            .map_err(|e| anyhow!("open {SNAT_IPLIST_MAP}: {e}"))?;
        let seed = SnatEntry {
            ip: egress.source.octets(),
            current_port: SNAT_FIRST_PORT,
        };
        snat.set(0, &seed, 0)
            .map_err(|e| anyhow!("write {SNAT_IPLIST_MAP}: {e}"))?;
        for name in [FROM_SANDBOX_PROGRAM, FROM_WORLD_PROGRAM, ARP_PROGRAM] {
            let program: &mut SchedClassifier = bpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("eBPF program {name} is missing"))?
                .try_into()
                .map_err(|e| anyhow!("{name} is not a classifier: {e}"))?;
            program
                .load()
                .with_context(|| format!("load eBPF program {name}"))?;
        }
        // Replies come in on the egress interface, so that hook is wired here;
        // the per-veth hooks follow as sandboxes appear.
        let program: &mut SchedClassifier = bpf
            .program_mut(FROM_WORLD_PROGRAM)
            .ok_or_else(|| anyhow!("eBPF program {FROM_WORLD_PROGRAM} is missing"))?
            .try_into()
            .map_err(|e| anyhow!("{FROM_WORLD_PROGRAM} is not a classifier: {e}"))?;
        program
            .attach(egress_ifindex, TcAttachType::Ingress)
            .with_context(|| format!("attach {FROM_WORLD_PROGRAM} to {}", egress.interface))?;
        let frames = bpf
            .take_map(FRAMES_MAP)
            .ok_or_else(|| anyhow!("eBPF map {FRAMES_MAP} is missing"))?;
        let frames = RingBuf::try_from(frames).map_err(|e| anyhow!("open {FRAMES_MAP}: {e}"))?;
        Ok((Self { bpf }, FrameLog { frames }))
    }

    /// Takes the session tables out of the object and hands them to the expiry
    /// sweep, which the daemon runs on a thread of its own.
    ///
    /// `egress_ip` is the host address the source-NAT table was seeded with; an
    /// egress session key plus that address is all it takes to build the reply
    /// direction's ingress key, so the sweep only has to walk one table.
    pub fn expiry(&mut self, egress_ip: Ipv4Addr) -> Result<SessionExpiry> {
        let egress = self
            .bpf
            .take_map(EGRESS_SESSION_MAP)
            .ok_or_else(|| anyhow!("eBPF map {EGRESS_SESSION_MAP} is missing"))?;
        let ingress = self
            .bpf
            .take_map(INGRESS_SESSION_MAP)
            .ok_or_else(|| anyhow!("eBPF map {INGRESS_SESSION_MAP} is missing"))?;
        Ok(SessionExpiry::new(egress, ingress, egress_ip.octets()))
    }

    /// Attaches both classifiers to the ingress hook of one sandbox veth.
    ///
    /// The from-sandbox handler goes first: classifiers on one hook run in
    /// attach order, and the ARP responder redirects the frames it handles, so
    /// it would hide them from a program attached after it.
    pub fn attach(&mut self, interface: &str) -> Result<()> {
        let index = interface_index(interface)?;
        for name in [FROM_SANDBOX_PROGRAM, ARP_PROGRAM] {
            let program: &mut SchedClassifier = self
                .bpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("eBPF program {name} is missing"))?
                .try_into()
                .map_err(|e| anyhow!("{name} is not a classifier: {e}"))?;
            program
                .attach(index, TcAttachType::Ingress)
                .with_context(|| format!("attach {name} to {interface}"))?;
        }
        Ok(())
    }
}

/// Debug feed of the frames the from-sandbox program reports.
pub struct FrameLog {
    frames: RingBuf<MapData>,
}

impl FrameLog {
    /// Logs reported frames until the process ends; blocks the calling thread.
    ///
    /// The ring buffer is pollable, but a short sleep between empty polls is
    /// enough for a human-readable log and keeps the code free of an event
    /// loop dependency.
    pub fn run(mut self) {
        let mut window = Instant::now();
        let mut logged = 0;
        let mut suppressed = 0u64;
        loop {
            let mut idle = true;
            while let Some(item) = self.frames.next() {
                idle = false;
                let Some(event) = FrameEvent::decode(&item) else {
                    continue;
                };
                if logged == LOG_BUDGET && window.elapsed() < Duration::from_secs(1) {
                    suppressed += 1;
                    continue;
                }
                if window.elapsed() >= Duration::from_secs(1) {
                    logged = 0;
                    window = Instant::now();
                }
                logged += 1;
                eprintln!("{}", event.describe());
            }
            if suppressed > 0 && window.elapsed() >= Duration::from_secs(1) {
                eprintln!("from-sandbox: {suppressed} frames not logged (limit {LOG_BUDGET}/s)");
                suppressed = 0;
            }
            if idle {
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// Mirror of `FrameEvent` in `sbxd-ebpf/src/from_sandbox.rs`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct FrameEvent {
    timestamp_ns: u64,
    ifindex: u32,
    len: u32,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    ethertype: u16,
    ip_proto: u8,
    tcp_flags: u8,
    arp_op: u8,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
}

const _: () = assert!(size_of::<FrameEvent>() == 48);

/// Mirror of `SnatEntry` in `sbxd-ebpf/src/snat.rs`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct SnatEntry {
    ip: [u8; 4],
    current_port: u16,
}

// SAFETY: both fields are integers with no padding; every bit pattern is a
// valid value.
unsafe impl Pod for SnatEntry {}

const _: () = assert!(size_of::<SnatEntry>() == 6);

impl FrameEvent {
    /// Reads one event off the ring buffer.
    ///
    /// Entries are handed back as raw bytes; the read is unaligned so the
    /// decode never depends on where the ring buffer mapped.
    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != size_of::<Self>() {
            return None;
        }
        // SAFETY: `FrameEvent` is `repr(C)` with integer fields only, so every
        // bit pattern is a valid value, and `read_unaligned` has no alignment
        // requirement.
        Some(unsafe { ptr::read_unaligned(bytes.as_ptr().cast()) })
    }

    /// One log line: link addresses, then the protocol view of the frame.
    fn describe(&self) -> String {
        let transport = match self.ethertype {
            ETH_P_IPV4 => match self.ip_proto {
                IPPROTO_ICMP => format!("icmp {} > {}", ip(self.src_ip), ip(self.dst_ip)),
                IPPROTO_TCP => format!(
                    "tcp {}:{} > {}:{} {}",
                    ip(self.src_ip),
                    self.src_port,
                    ip(self.dst_ip),
                    self.dst_port,
                    tcp_flags(self.tcp_flags)
                ),
                IPPROTO_UDP => format!(
                    "udp {}:{} > {}:{}",
                    ip(self.src_ip),
                    self.src_port,
                    ip(self.dst_ip),
                    self.dst_port
                ),
                proto => format!("ip proto={proto} {} > {}", ip(self.src_ip), ip(self.dst_ip)),
            },
            ETH_P_ARP => format!(
                "arp {} {} ? {}",
                match self.arp_op {
                    1 => "request",
                    2 => "reply",
                    _ => "other",
                },
                ip(self.src_ip),
                ip(self.dst_ip)
            ),
            ethertype => format!("ethertype=0x{ethertype:04x}"),
        };
        format!(
            "from-sandbox {} len={} {} -> {} {transport}",
            interface_name(self.ifindex),
            self.len,
            net::format_mac(self.src_mac),
            net::format_mac(self.dst_mac)
        )
    }
}

/// Looks up the kernel interface index by name.
fn interface_index(interface: &str) -> Result<u32> {
    let name = CString::new(interface)
        .with_context(|| format!("interface name {interface:?} contains a NUL"))?;
    // SAFETY: `name` is a NUL-terminated C string.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error()).with_context(|| format!("no interface named {interface}"))
    } else {
        Ok(index)
    }
}

/// The name an interface index currently has, if any.
fn interface_name(index: u32) -> String {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `name` is writable for `IF_NAMESIZE` bytes.
    let filled = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
    if filled.is_null() {
        return format!("if{index}");
    }
    // SAFETY: on success the call NUL-terminated the buffer.
    unsafe { CStr::from_ptr(filled) }
        .to_string_lossy()
        .into_owned()
}

fn ip(address: [u8; 4]) -> String {
    format!(
        "{}.{}.{}.{}",
        address[0], address[1], address[2], address[3]
    )
}

/// TCP flags as the one-letter abbreviations `tcpdump` and Wireshark use.
fn tcp_flags(flags: u8) -> String {
    const FLAGS: [(u8, char); 8] = [
        (0x01, 'F'),
        (0x02, 'S'),
        (0x04, 'R'),
        (0x08, 'P'),
        (0x10, 'A'),
        (0x20, 'U'),
        (0x40, 'E'),
        (0x80, 'C'),
    ];
    let set: String = FLAGS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, letter)| *letter)
        .collect();
    format!("[{set}]")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> FrameEvent {
        FrameEvent {
            timestamp_ns: 0,
            ifindex: 0,
            len: 60,
            src_ip: [0; 4],
            dst_ip: [0; 4],
            src_port: 0,
            dst_port: 0,
            ethertype: 0,
            ip_proto: 0,
            tcp_flags: 0,
            arp_op: 0,
            src_mac: [0; 6],
            dst_mac: [0; 6],
        }
    }

    #[test]
    fn frame_event_matches_kernel_layout() {
        assert_eq!(size_of::<FrameEvent>(), 48);
        assert_eq!(std::mem::align_of::<FrameEvent>(), 8);
    }

    #[test]
    fn decode_rejects_other_lengths() {
        assert!(FrameEvent::decode(&[]).is_none());
        assert!(FrameEvent::decode(&[0; 47]).is_none());
        assert!(FrameEvent::decode(&[0; 49]).is_none());
        assert!(FrameEvent::decode(&[0; 48]).is_some());
    }

    #[test]
    fn describes_tcp() {
        let event = FrameEvent {
            ethertype: ETH_P_IPV4,
            ip_proto: IPPROTO_TCP,
            src_ip: [169, 254, 0, 21],
            dst_ip: [1, 1, 1, 1],
            src_port: 40_000,
            dst_port: 443,
            tcp_flags: 0x02,
            ..event()
        };
        let line = event.describe();
        assert!(
            line.ends_with("tcp 169.254.0.21:40000 > 1.1.1.1:443 [S]"),
            "{line}"
        );
    }

    #[test]
    fn describes_arp_request() {
        let event = FrameEvent {
            ethertype: ETH_P_ARP,
            arp_op: 1,
            src_ip: [169, 254, 0, 21],
            dst_ip: [169, 254, 0, 1],
            ..event()
        };
        let line = event.describe();
        assert!(
            line.ends_with("arp request 169.254.0.21 ? 169.254.0.1"),
            "{line}"
        );
    }

    #[test]
    fn tcp_flag_letters() {
        assert_eq!(tcp_flags(0x12), "[SA]");
        assert_eq!(tcp_flags(0x18), "[PA]");
        assert_eq!(tcp_flags(0x00), "[]");
    }
}
