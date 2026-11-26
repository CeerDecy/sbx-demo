//! Userspace side of the session tables: the mirrors of the kernel values and
//! the sweep that expires sessions.
//!
//! A session has no signal that says it is over — a sandbox can vanish
//! mid-handshake, a UDP flow never says goodbye — so every entry carries the
//! time it was last used and the state its connection reached, and this sweep
//! removes the ones that have been quiet for longer than that state allows.
//! The timeouts are the daemon's policy; the datapath only records the state.

use aya::{
    Pod,
    maps::{HashMap, Map, MapData},
};
use std::{mem::size_of, thread, time::Duration};

/// Mirrors `SessionKey` in `sbxd-ebpf/src/session.rs`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SessionKey {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    _pad: u8,
}

const _: () = assert!(size_of::<SessionKey>() == 14);

// SAFETY: every field is an integer or an array of them, and the explicit pad
// leaves no byte the kernel could fill that Rust would not name.
unsafe impl Pod for SessionKey {}

/// Mirrors `EgressSessionKey` in `sbxd-ebpf/src/session.rs`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EgressSessionKey {
    veth_ifindex: u32,
    flow: SessionKey,
    _pad: u16,
}

const _: () = assert!(size_of::<EgressSessionKey>() == 20);

// SAFETY: as above.
unsafe impl Pod for EgressSessionKey {}

/// Mirrors `EgressSessionValue` in `sbxd-ebpf/src/session.rs`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EgressSessionValue {
    /// `bpf_ktime_get_ns` of the last frame in either direction.
    access_time: u64,
    snat_port: u16,
    state: u8,
    _pad: [u8; 5],
}

const _: () = assert!(size_of::<EgressSessionValue>() == 16);

// SAFETY: as above.
unsafe impl Pod for EgressSessionValue {}

/// Connection states, mirroring the `TCP_*` and `UDP_*` constants in
/// `sbxd-ebpf/src/session.rs`.
const TCP_SYN_SENT: u8 = 0;
const TCP_SYN_RECV: u8 = 1;
const TCP_ESTABLISHED: u8 = 2;
const TCP_CLOSE_WAIT: u8 = 3;
const TCP_FIN_WAIT: u8 = 4;
const TCP_TIME_WAIT: u8 = 5;
const TCP_LAST_ACK: u8 = 6;
const TCP_CLOSE: u8 = 7;
const UDP_UNREPLIED: u8 = 8;
const UDP_REPLIED: u8 = 9;
const ICMP_PENDING: u8 = 10;

const SECOND: u64 = 1_000_000_000;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 60 * MINUTE;

/// How long a session in `state` may stay silent before it is removed.
///
/// A silent ESTABLISHED connection is worth keeping for hours; a handshake
/// that never completed, or a close that never finished, is not. An echo has
/// no connection at all, just one reply to wait for.
fn lifetime(state: u8) -> u64 {
    match state {
        TCP_ESTABLISHED => 3 * HOUR,
        TCP_SYN_SENT | TCP_SYN_RECV | TCP_CLOSE_WAIT => MINUTE,
        TCP_FIN_WAIT | TCP_TIME_WAIT => 2 * MINUTE,
        TCP_LAST_ACK => 30 * SECOND,
        TCP_CLOSE => 10 * SECOND,
        UDP_REPLIED => 180 * SECOND,
        UDP_UNREPLIED | ICMP_PENDING => 30 * SECOND,
        // Any state a future datapath adds that this daemon does not know:
        // expire quickly rather than leak.
        _ => 30 * SECOND,
    }
}

/// How often the tables are swept.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// The expiry sweep, holding the session tables once the datapath has given
/// them up.
pub struct SessionExpiry {
    egress: Map,
    ingress: Map,
    /// The host address that is the ingress key's destination, so the paired
    /// ingress entry can be built from an egress one.
    egress_ip: [u8; 4],
}

impl SessionExpiry {
    pub fn new(egress: Map, ingress: Map, egress_ip: [u8; 4]) -> Self {
        Self {
            egress,
            ingress,
            egress_ip,
        }
    }

    /// Sweeps the tables every [`SWEEP_INTERVAL`] until the process ends;
    /// blocks the calling thread.
    pub fn run(mut self) {
        loop {
            thread::sleep(SWEEP_INTERVAL);
            // The typed views borrow the map data, so they are rebuilt for
            // every pass instead of being kept.
            let (Ok(mut egress), Ok(mut ingress)) = (
                HashMap::<&mut MapData, EgressSessionKey, EgressSessionValue>::try_from(
                    &mut self.egress,
                ),
                HashMap::<&mut MapData, SessionKey, [u8; 24]>::try_from(&mut self.ingress),
            ) else {
                continue;
            };
            expire(&mut egress, &mut ingress, self.egress_ip);
        }
    }
}

/// Removes every session whose state no longer justifies keeping it.
fn expire(
    egress: &mut HashMap<&mut MapData, EgressSessionKey, EgressSessionValue>,
    ingress: &mut HashMap<&mut MapData, SessionKey, [u8; 24]>,
    egress_ip: [u8; 4],
) {
    let now = monotonic_ns();
    // Deleting while iterating is not safe. The iterator asks the kernel
    // for the key after the one it last returned, and a key that is no
    // longer in the map makes the kernel start over from the first entry —
    // so a deletion mid-pass can send the sweep back to the beginning.
    // Expired keys are collected first and removed in a second pass.
    let mut expired = Vec::new();
    for entry in egress.iter() {
        let Ok((key, value)) = entry else {
            // The entry vanished between the key listing and the lookup;
            // the next entry is still reachable, so only this one is lost.
            continue;
        };
        if now < value.access_time || now - value.access_time < lifetime(value.state) {
            continue;
        }
        expired.push((key, value));
    }
    for (key, value) in expired {
        // The reply direction's key is this one with the sandbox's address
        // and port replaced by the host's address and SNAT port.
        let ingress_key = SessionKey {
            src_ip: key.flow.dst_ip,
            dst_ip: egress_ip,
            src_port: key.flow.dst_port,
            dst_port: value.snat_port,
            protocol: key.flow.protocol,
            _pad: 0,
        };
        let _ = egress.remove(&key);
        let _ = ingress.remove(&ingress_key);
    }
}

/// `CLOCK_MONOTONIC` in nanoseconds, the clock `bpf_ktime_get_ns` reads.
fn monotonic_ns() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` only writes to the struct it is given, and
    // `CLOCK_MONOTONIC` always exists.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now);
    }
    now.tv_sec as u64 * SECOND + now.tv_nsec as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetimes_follow_the_table() {
        assert_eq!(lifetime(TCP_ESTABLISHED), 3 * HOUR);
        assert_eq!(lifetime(TCP_SYN_SENT), MINUTE);
        assert_eq!(lifetime(TCP_SYN_RECV), MINUTE);
        assert_eq!(lifetime(TCP_CLOSE_WAIT), MINUTE);
        assert_eq!(lifetime(TCP_FIN_WAIT), 2 * MINUTE);
        assert_eq!(lifetime(TCP_TIME_WAIT), 2 * MINUTE);
        assert_eq!(lifetime(TCP_LAST_ACK), 30 * SECOND);
        assert_eq!(lifetime(TCP_CLOSE), 10 * SECOND);
        assert_eq!(lifetime(UDP_UNREPLIED), 30 * SECOND);
        assert_eq!(lifetime(UDP_REPLIED), 180 * SECOND);
        assert_eq!(lifetime(ICMP_PENDING), 30 * SECOND);
        assert_eq!(lifetime(u8::MAX), 30 * SECOND);
    }

    #[test]
    fn monotonic_clock_advances() {
        let first = monotonic_ns();
        let second = monotonic_ns();
        assert!(second >= first);
        // The clock counts from boot, so it is far larger than a second.
        assert!(first > SECOND);
    }
}
