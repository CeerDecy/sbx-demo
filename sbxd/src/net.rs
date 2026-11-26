//! Host-side networking: the gateway L2 device and one veth pair per sandbox.
//!
//! Forwarding and ARP for the gateway address are not implemented here; they
//! belong to the eBPF datapath. This module only puts the carrier in place.

use crate::{command, error};
use anyhow::{Context, Result, anyhow};
use sbx_proto::ErrorCode;
use std::{
    collections::BTreeSet,
    fs,
    net::{IpAddr, Ipv4Addr, UdpSocket},
    path::Path,
    thread,
    time::{Duration, Instant},
};

/// Fixed hardware address for every sandbox eth0: locally administered and
/// unicast (0x02), and the next three octets spell "SBX" in ASCII, so frames
/// from a sandbox are obvious at a glance in a capture.
pub const SANDBOX_MAC: &str = "02:53:42:58:00:21";

/// Host-side L2 device that stands in for the sandbox gateway. It carries no
/// addresses on purpose: the eBPF datapath redirects frames to and from it.
pub const GATEWAY_LINK: &str = "sbx0";
pub const GATEWAY_MAC: &str = "02:53:42:58:00:01";

/// Next hop of every sandbox's default route.
const GATEWAY_ADDR: &str = "169.254.0.1";

/// Index range handed out to sandboxes; the top of the range is the pool size.
const MAX_INDEX: u32 = 127;

/// Creates the gateway L2 device if it is missing and pins its MAC. Runs on
/// every daemon start, so a reboot or a manual `ip link del` self-heals.
pub fn ensure_gateway_link() -> Result<()> {
    if command::status("ip", &["link", "show", "dev", GATEWAY_LINK]).is_err() {
        command::status("ip", &["link", "add", GATEWAY_LINK, "type", "dummy"])
            .with_context(|| format!("create {GATEWAY_LINK}"))?;
    }
    command::status("ip", &["link", "set", GATEWAY_LINK, "address", GATEWAY_MAC])
        .with_context(|| format!("set {GATEWAY_LINK} address"))?;
    // Bringing a device up makes the kernel add an IPv6 link-local address.
    // This link must stay addressless, so IPv6 is switched off for it first;
    // that also removes any link-local left over from an earlier run.
    let sysctl = format!("net.ipv6.conf.{GATEWAY_LINK}.disable_ipv6=1");
    command::status("sysctl", &["-q", "-w", &sysctl])
        .with_context(|| format!("disable IPv6 on {GATEWAY_LINK}"))?;
    command::status("ip", &["link", "set", GATEWAY_LINK, "up"])
        .with_context(|| format!("bring {GATEWAY_LINK} up"))?;
    Ok(())
}

/// Port the startup probe targets; the discard service needs no listener.
const PROBE_PORT: u16 = 9;
/// How long the kernel gets to answer ARP before startup gives up.
const NEIGHBOUR_TIMEOUT: Duration = Duration::from_secs(2);
const NEIGHBOUR_POLL: Duration = Duration::from_millis(50);

const RTF_UP: u32 = 0x1;
const RTF_GATEWAY: u32 = 0x2;
const ATF_COM: u32 = 0x2;

/// The path a sandbox's traffic takes once it leaves the host: the address it
/// appears to come from, and the hardware address it is sent to.
pub struct Egress {
    /// Name of the interface the default route uses.
    pub interface: String,
    /// IPv4 address of that interface; traffic from a sandbox is rewritten to
    /// carry it as the source address.
    pub source: Ipv4Addr,
    /// Hardware address of that interface; rewritten frames carry it as their
    /// source address at the link layer.
    pub source_mac: [u8; 6],
    /// Hardware address of the default route's next hop; every forwarded frame
    /// is sent there.
    pub next_hop_mac: [u8; 6],
}

/// Resolves the host's egress path on the default route.
///
/// This has to be known before the eBPF programs are loaded: the daemon bakes
/// the addresses into them as constants. The kernel only resolves a neighbour
/// once traffic is actually sent, so a datagram to the discard port warms the
/// table first; the payload is irrelevant, the ARP round trip is not. The same
/// datagram socket reports the source address the kernel picked for that
/// route, and the interface MAC comes from sysfs.
pub fn egress() -> Result<Egress> {
    let routes = fs::read_to_string("/proc/net/route").context("read /proc/net/route")?;
    let (interface, gateway) = parse_default_route(&routes)
        .ok_or_else(|| anyhow!("no default route with a gateway in /proc/net/route"))?;
    if gateway.is_unspecified() {
        return Err(anyhow!(
            "default route has no next hop address; cannot resolve its MAC"
        ));
    }
    let socket =
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).context("open the neighbour probe socket")?;
    // Connecting on UDP only records the route; the send is what makes the
    // kernel resolve the gateway's hardware address on that route's device.
    socket
        .connect((gateway, PROBE_PORT))
        .with_context(|| format!("route traffic to {gateway}"))?;
    let source = match socket.local_addr()?.ip() {
        IpAddr::V4(source) => source,
        IpAddr::V6(source) => {
            return Err(anyhow!("default route uses IPv6 source address {source}"));
        }
    };
    socket
        .send(b"\0")
        .with_context(|| format!("probe {gateway} for its MAC"))?;

    let deadline = Instant::now() + NEIGHBOUR_TIMEOUT;
    loop {
        if let Some(next_hop_mac) = neighbour_mac(gateway)? {
            return Ok(Egress {
                source_mac: interface_mac(&interface)?,
                interface,
                source,
                next_hop_mac,
            });
        }
        if Instant::now() >= deadline {
            return Err(anyhow!("no ARP reply from default gateway {gateway}"));
        }
        thread::sleep(NEIGHBOUR_POLL);
    }
}

/// Hardware address of the interface with this name.
fn interface_mac(interface: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{interface}/address");
    let text = fs::read_to_string(&path).with_context(|| format!("read {path}"))?;
    parse_mac(text.trim()).ok_or_else(|| anyhow!("{path} does not hold a MAC address"))
}

/// The resolved hardware address of `ip`, if the kernel has one.
fn neighbour_mac(ip: Ipv4Addr) -> Result<Option<[u8; 6]>> {
    let table = fs::read_to_string("/proc/net/arp").context("read /proc/net/arp")?;
    Ok(parse_neighbour(&table, ip))
}

/// Interface and gateway of the first default route that has one in
/// `/proc/net/route`.
///
/// Addresses in this table are the four bytes of the address read as a native
/// `u32`, so the hex is parsed and turned back into bytes in host order. A
/// default route needs `RTF_UP` and `RTF_GATEWAY`: without the latter it is a
/// device route with no next hop to resolve.
fn parse_default_route(table: &str) -> Option<(String, Ipv4Addr)> {
    table.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace();
        let interface = fields.next()?;
        let destination = fields.next()?;
        let gateway = fields.next()?;
        let flags = parse_hex(fields.next()?)?;
        if destination != "00000000" || flags & (RTF_UP | RTF_GATEWAY) != (RTF_UP | RTF_GATEWAY) {
            return None;
        }
        let address = u32::from_str_radix(gateway, 16).ok()?;
        Some((interface.to_owned(), Ipv4Addr::from(address.to_le_bytes())))
    })
}

/// The complete (`ATF_COM`) `/proc/net/arp` entry for `ip`.
fn parse_neighbour(table: &str, ip: Ipv4Addr) -> Option<[u8; 6]> {
    table.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace();
        let address: Ipv4Addr = fields.next()?.parse().ok()?;
        let _hw_type = fields.next()?;
        let flags = parse_hex(fields.next()?)?;
        let hardware = fields.next()?;
        if address != ip || flags & ATF_COM == 0 {
            return None;
        }
        parse_mac(hardware)
    })
}

/// Parses a hex field, with or without the `0x` prefix the kernel prints in
/// some of these tables.
fn parse_hex(text: &str) -> Option<u32> {
    u32::from_str_radix(text.strip_prefix("0x").unwrap_or(text), 16).ok()
}

/// Parses a `aa:bb:cc:dd:ee:ff` hardware address; nothing shorter or longer
/// counts.
fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut octets = text.split(':');
    for octet in &mut mac {
        *octet = u8::from_str_radix(octets.next()?, 16).ok()?;
    }
    octets.next().is_none().then_some(mac)
}

/// Renders a hardware address as `aa:bb:cc:dd:ee:ff`.
pub fn format_mac(address: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        address[0], address[1], address[2], address[3], address[4], address[5]
    )
}

/// Whether a network namespace with this name exists on the host.
pub fn namespace_exists(ns: &str) -> bool {
    Path::new("/var/run/netns").join(ns).exists()
}

/// Names of the sandbox veths currently present on the host.
pub fn sandbox_veths() -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str()
            && name.starts_with("v-")
        {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

/// Creates the empty network namespace `ns`.
pub fn create_namespace(ns: &str) -> Result<()> {
    command::status("ip", &["netns", "add", ns])
        .map_err(|e| error::coded(ErrorCode::IoError, e.to_string()))
}

/// Removes namespace `ns`. Best effort: it may already be gone.
pub fn delete_namespace(ns: &str) {
    let _ = command::status("ip", &["netns", "del", ns]);
}

/// Wires the sandbox namespace up.
///
/// One veth pair: the host end `veth` stays here for the eBPF datapath, the
/// peer is named `eth0` and lands directly in `ns`. The kernel moves frames
/// between the two ends with no userspace involvement.
pub fn attach_interface(ns: &str, veth: &str, ident: &str) -> Result<()> {
    let ident_cidr = format!("{ident}/32");
    let steps: &[&[&str]] = &[
        &[
            "link", "add", veth, "type", "veth", "peer", "name", "eth0", "netns", ns,
        ],
        &["link", "set", veth, "up"],
        &["netns", "exec", ns, "ip", "link", "set", "lo", "up"],
        // Every sandbox shares the same MAC, just like the ident address.
        &[
            "netns",
            "exec",
            ns,
            "ip",
            "link",
            "set",
            "eth0",
            "address",
            SANDBOX_MAC,
        ],
        &[
            "netns",
            "exec",
            ns,
            "ip",
            "addr",
            "add",
            &ident_cidr,
            "dev",
            "eth0",
        ],
        &["netns", "exec", ns, "ip", "link", "set", "eth0", "up"],
        &[
            "netns",
            "exec",
            ns,
            "ip",
            "route",
            "add",
            "default",
            "via",
            GATEWAY_ADDR,
            "dev",
            "eth0",
            "onlink",
        ],
    ];
    for step in steps {
        command::status("ip", step).map_err(|e| error::coded(ErrorCode::IoError, e.to_string()))?;
    }
    Ok(())
}

// Lowest free index. Indices held by a live veth or by a recorded sandbox are
// both off limits, so a freed index is reused instead of the pool drifting
// upward on every create/remove cycle.
pub fn allocate_index(recorded: &[u32]) -> Result<u32> {
    let mut taken: BTreeSet<u32> = live_indices()?.into_iter().collect();
    taken.extend(recorded.iter().copied());
    (1..=MAX_INDEX)
        .find(|index| !taken.contains(index))
        .ok_or_else(|| {
            error::coded(
                ErrorCode::CommandFailed,
                format!("sandbox address pool exhausted (indices 1..{MAX_INDEX})"),
            )
        })
}

/// Indices derived from the leaf octet of each `v-<id>` veth address.
pub(crate) fn derive_indices(output: &str) -> Vec<u32> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.get(1).is_none_or(|name| !name.starts_with("v-")) {
                return None;
            }
            fields
                .get(3)?
                .split('/')
                .next()?
                .rsplit('.')
                .next()?
                .parse::<u32>()
                .ok()
                .map(|octet| octet / 2)
        })
        .collect()
}

/// Indices currently held by live veth interfaces.
fn live_indices() -> Result<Vec<u32>> {
    let output = command::output("ip", &["-o", "-4", "addr", "show"])?;
    if !output.status.success() {
        return Err(error::coded(
            ErrorCode::CommandFailed,
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(derive_indices(&String::from_utf8_lossy(&output.stdout)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTES: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlo1\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
wlo1\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
";

    const ARP: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.0.1      0x1         0x2         a4:2b:8c:11:22:33     *        wlo1
192.168.0.9      0x1         0x0         00:00:00:00:00:00     *        wlo1
";

    #[test]
    fn default_route_is_read_in_host_byte_order() {
        assert_eq!(
            parse_default_route(ROUTES),
            Some(("wlo1".to_owned(), Ipv4Addr::new(192, 168, 0, 1)))
        );
    }

    #[test]
    fn default_route_without_a_gateway_is_skipped() {
        // A device route (flags 0001) is not a next hop.
        let table = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlo1\t00000000\t00000000\t0001\t0\t0\t600\t00000000\t0\t0\t0
";
        assert_eq!(parse_default_route(table), None);
    }

    #[test]
    fn table_without_a_default_route_has_no_gateway() {
        let only_lan = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlo1\t0000A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0
";
        assert_eq!(parse_default_route(only_lan), None);
        let header_only =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
        assert_eq!(parse_default_route(header_only), None);
        assert_eq!(parse_default_route(""), None);
    }

    #[test]
    fn neighbour_returns_the_complete_entry() {
        assert_eq!(
            parse_neighbour(ARP, Ipv4Addr::new(192, 168, 0, 1)),
            Some([0xa4, 0x2b, 0x8c, 0x11, 0x22, 0x33])
        );
    }

    #[test]
    fn neighbour_skips_incomplete_and_unrelated_entries() {
        // Present but unresolved.
        assert_eq!(parse_neighbour(ARP, Ipv4Addr::new(192, 168, 0, 9)), None);
        // Not in the table at all.
        assert_eq!(parse_neighbour(ARP, Ipv4Addr::new(192, 168, 0, 2)), None);
    }

    #[test]
    fn mac_addresses_parse_only_in_full() {
        assert_eq!(
            parse_mac("02:53:42:58:00:21"),
            Some([0x02, 0x53, 0x42, 0x58, 0x00, 0x21])
        );
        assert_eq!(parse_mac("02:53:42:58:00"), None);
        assert_eq!(parse_mac("02:53:42:58:00:21:00"), None);
        assert_eq!(parse_mac("02:53:42:58:00:zz"), None);
        assert_eq!(parse_mac(""), None);
    }

    #[test]
    fn hex_fields_accept_the_kernel_prefix() {
        assert_eq!(parse_hex("0x2"), Some(2));
        assert_eq!(parse_hex("0003"), Some(3));
        assert_eq!(parse_hex(""), None);
        assert_eq!(parse_hex("nonsense"), None);
    }

    #[test]
    fn mac_addresses_render_with_two_digits_per_octet() {
        assert_eq!(
            format_mac([0x02, 0x00, 0xab, 0xff, 0x10, 0x01]),
            "02:00:ab:ff:10:01"
        );
    }
}
