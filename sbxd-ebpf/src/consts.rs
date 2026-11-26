//! Wire-format constants shared by the datapath programs.

/// Length of an Ethernet II header, VLAN tags included in the payload.
pub const ETH_HDR_LEN: usize = 14;
/// Length of an IPv4 header without options.
pub const IPV4_HDR_LEN: usize = 20;

pub const ETH_P_IPV4: u16 = 0x0800;
pub const ETH_P_ARP: u16 = 0x0806;

/// Fixed hardware address of every sandbox's eth0; mirrors `net::SANDBOX_MAC`
/// in the daemon.
pub const SANDBOX_MAC: [u8; 6] = [0x02, 0x53, 0x42, 0x58, 0x00, 0x21];
/// Hardware address of the `sbx0` gateway device; mirrors `net::GATEWAY_MAC`.
pub const GATEWAY_MAC: [u8; 6] = [0x02, 0x53, 0x42, 0x58, 0x00, 0x01];

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// ICMP echo request; its identifier stands in for a source port.
pub const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMP echo reply; its identifier stands in for a destination port.
pub const ICMP_ECHO_REPLY: u8 = 0;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;
