# eBPF Datapath: Network Forwarding for gVisor Sandboxes

This document describes how `sbxd` moves packets between sandboxes and the
outside world with eBPF. It covers the topology, the programs and their attach
points, the maps and their layouts, the translation done in each direction, the
session lifecycle, and the operational limits that are not implemented yet.

## 1. Topology

Every sandbox runs gVisor (`runsc`) in its own network namespace and is
connected to the host by a veth pair. The host side is named `v-<id>`; the
sandbox side is `eth0`.

All sandboxes are configured identically, on purpose:

| Property | Value | Why one value for everyone |
| --- | --- | --- |
| Sandbox address | `169.254.0.21/32` | The datapath, not the address, tells flows apart |
| Sandbox MAC | `02:53:42:58:00:21` | Same |
| Default gateway | `169.254.0.1` | A dummy device `sbx0` on the host |
| Gateway MAC | `02:53:42:58:00:01` | Answered by the ARP responder |

```
        sandbox netns                         host                          world
 ┌──────────────────────┐        ┌──────────────────────────────┐
 │  eth0                │  veth  │  v-<id>          wlo1        │
 │  169.254.0.21/32  ───┼────────┼──▶ [TC ingress] ─────────────┼──▶ next hop
 │  gw 169.254.0.1      │        │      from_sandbox             │      (router)
 │  └─ ARP → sbxd_arp   │        │      arp                      │
 │                      │        │                               │
 │                      │        │  sbx0 (dummy, 169.254.0.1)    │
 │                      │        │                               │
 │   reply path         │        │  [TC ingress on wlo1]         │
 │   ◀──────────────────┼────────┼── from_world (redirect)       │◀── replies
 └──────────────────────┘        └──────────────────────────────┘
```

Because the address and MAC are shared, **a five tuple alone does not identify
a sandbox**. The session tables key on it anyway, and where that is ambiguous
the veth index is added to the key (see `EgressSessionKey`).

## 2. Why TC eBPF instead of iptables/nftables

- **Per-flow state at the edge.** The daemon owns one translation table per
  direction and can inspect it at any time (`bpftool map dump`); there is no
  second copy of the truth in conntrack.
- **One redirect, no host stack.** A translated frame is handed straight from
  the veth to the egress interface with `bpf_redirect`, so the host routing
  table, netfilter and `ip_forward` are not on the path at all.
- **Scale.** Sessions are a `BPF_F_NO_PREALLOC` hash map with a one-million
  ceiling that costs nothing until entries exist.
- **Sandboxes keep their own stack.** gVisor stays the only IP stack in the
  namespace; nothing in the sandbox has to understand NAT.

## 3. Programs and attach points

All three are TC classifiers (`sched_cls`), attached to the **ingress** hook.

| Program | Hook | Job |
| --- | --- | --- |
| `sbxd_from_sandbox` | TC ingress on every `v-<id>` | SNAT, session creation, redirect out the egress interface |
| `sbxd_arp` | TC ingress on every `v-<id>` | Answer ARP for `169.254.0.1` |
| `sbxd_from_world` | TC ingress on the egress interface (`wlo1`) | De-NAT, redirect into the owning veth |

`sbxd_from_sandbox` is attached **before** `sbxd_arp`: classifiers on one hook
run in attach order, and the ARP responder redirects the frames it handles, so a
program attached after it would never see them.

The return codes matter:

| Return | Meaning | Used for |
| --- | --- | --- |
| `TC_ACT_REDIRECT` | Frame is consumed by `bpf_redirect` | Translated frames |
| `TC_ACT_UNSPEC` | Next classifier on the hook, then the host stack | Frames we do not own |
| `TC_ACT_SHOT` | Dropped | Stray segments, full tables, failed rewrites |

`TC_ACT_UNSPEC` (not `TC_ACT_OK`) is what lets a non-TCP/UDP frame fall through
to the ARP responder behind it.

Links are TCX, i.e. owned by an fd. Dropping the `Datapath` detaches every
program, so the datapath lives exactly as long as the daemon.

### Load-time constants

Values the daemon resolves once and bakes into `.rodata` as aya `Global<T>`
statics before the programs are verified:

| Symbol | Source | Consumer |
| --- | --- | --- |
| `NEXT_HOP_MAC` | `/proc/net/arp` after a UDP probe wakes ARP | source MAC of rewritten frames |
| `EGRESS_MAC` | `/sys/class/net/<if>/address` | source MAC of rewritten frames |
| `EGRESS_IFINDEX` | `if_nametoindex` | target of `bpf_redirect` |
| `SANDBOX_IP` | daemon config (`169.254.0.21`) | destination of returning frames |

The source port counter and egress address live in a map instead, because the
counter has to change at runtime: `SNAT_IPLIST` is an `Array` of one
`SnatEntry { ip: [u8; 4], current_port: u16 }`, seeded by userspace with the
egress address and port `30000`.

## 4. Maps

| Map | Type | Key | Value | Ceiling |
| --- | --- | --- | --- | --- |
| `SNAT_IPLIST` | `Array` | `u32` (only 0) | `SnatEntry`, 6 bytes | 1 |
| `INGRESS_SESSION` | `HashMap`, `BPF_F_NO_PREALLOC` | `SessionKey`, 14 bytes | `IngressSessionValue`, 24 bytes | 1 048 576 |
| `EGRESS_SESSION` | `HashMap`, `BPF_F_NO_PREALLOC` | `EgressSessionKey`, 20 bytes | `EgressSessionValue`, 16 bytes | 1 048 576 |
| `FRAMES` | `RingBuf` | — | `FrameEvent`, 48 bytes | 256 KiB |

```text
SessionKey           src_ip[4] dst_ip[4] src_port u16 dst_port u16 protocol u8 _pad u8
IngressSessionValue  access_time u64 | sbx_mac[6] sbx_port u16 | veth_ifindex u32 | state u8 _pad[3]
EgressSessionKey     veth_ifindex u32 | flow: SessionKey | _pad u16
EgressSessionValue   access_time u64 | snat_port u16 | state u8 _pad[5]
```

All structs are `repr(C)` with explicit padding and a `const _: () =
assert!(size_of::<T>() == N)` both in the eBPF crate and in its userspace
mirror, so a layout drift fails the build rather than corrupting the map.

Ports inside keys and values are stored in **network byte order**, exactly as
they appear on the wire, so a key can be built from a frame without swapping.

### Why two session tables

- `INGRESS_SESSION` is keyed by the **reply's** tuple: `{peer, peer_port,
  egress_ip, snat_port, proto}`. A returning frame finds its sandbox with one
  lookup on its own headers.
- `EGRESS_SESSION` is keyed by the **sandbox's** tuple plus the veth index:
  `{veth_ifindex, {sandbox_ip, sandbox_port, peer, peer_port, proto}}`. It is
  what makes a retransmitted SYN reuse the port it was already given. The veth
  index is required because every sandbox shares one address and one MAC.

## 5. Egress path — `sbxd_from_sandbox`

Frames are parsed by the shared `flow::ipv4_flow`, which accepts IPv4 without
options carrying TCP, UDP, or an ICMP echo (see §8). Anything else is passed on
untouched.

1. Read the veth index from `__sk_buff.ifindex`.
2. Read the egress address from `SNAT_IPLIST[0].ip`.
3. Build the `EgressSessionKey` and look up `EGRESS_SESSION`.
   - Miss and TCP without SYN → **drop**. A segment that belongs to no session
     and opens none is stray and must not mint one.
   - Miss otherwise → take the next port from `SNAT_IPLIST` (wrap:
     `(p + 1) % 30000 + 30000`), insert `EgressSessionValue { access_time,
     snat_port, state = initial_state(proto) }`.
   - Hit → reuse the recorded `snat_port`.
4. Rewrite the link header: source = `EGRESS_MAC`, destination = `NEXT_HOP_MAC`.
5. Rewrite the IP source to the egress address and recompute the IPv4 header
   checksum; adjust the transport checksum incrementally for the address and
   port; store the SNAT port (or ICMP identifier) at `flow.src_field()`.
6. Build the reply-direction key `{src: dst_ip, src_port: dst_port, dst:
   egress_ip, dst_port: snat_port}`.
7. New session: insert `IngressSessionValue { access_time, sbx_mac =
   SANDBOX_MAC, sbx_port = original source port/identifier, veth_ifindex,
   state }`. Existing session: move the state with `sandbox_packet()` and
   refresh `access_time` on both halves.
8. `bpf_redirect(EGRESS_IFINDEX, 0)`; success → `TC_ACT_REDIRECT`, failure →
   `TC_ACT_SHOT`.

Nothing is ever removed here. A finished flow is left in `TIME_WAIT`/`CLOSE`
so late segments still translate; expiry is the userspace sweep's job (§9).

## 6. Ingress path — `sbxd_from_world`

Attached to the egress interface's ingress hook, this sees **all** inbound
frames, most of which belong to the host itself.

1. Parse; only an ICMP echo **reply** is considered among ICMP (`type 0`).
2. Look the frame's own five tuple up in `INGRESS_SESSION`.
   - Miss → `TC_ACT_UNSPEC`: the host stack gets the frame untouched.
3. Copy `veth_ifindex`, `sbx_mac`, `sbx_port` and the current state out of the
   entry before any further helper call.
4. Rewrite the link header: source = `GATEWAY_MAC` (as if it came from the
   sandbox's gateway), destination = the sandbox's MAC.
5. Rewrite the destination address to `SANDBOX_IP`, adjust checksums, store
   `sbx_port` at `flow.dst_field()`.
6. Build the matching `EgressSessionKey` (reverse flow, sandbox address and
   port in place of the egress address and SNAT port) and refresh
   `access_time` and the state in **both** tables with `world_packet()`.
7. `bpf_redirect(veth_ifindex, 0)`.

## 7. Checksums

- **IPv4 header:** recomputed from the 20 header bytes with the checksum field
  zeroed first (`flow::set_ip`). Using an incremental fix here would be trivial
  too, but the header is already on the stack for the address rewrite.
- **TCP/UDP:** adjusted incrementally, RFC 1624 equation 3, for the two
  16-bit words of the address that changed in the pseudo-header plus the port
  word. The payload is never read.
  - UDP with checksum `0` (sender did not compute one) is left at `0`.
  - A UDP checksum that computes to `0` is stored as `0xffff`.
- **ICMP echo:** no pseudo-header; only the identifier word is replaced.

A caveat worth knowing: gVisor hands TCP segments (other than the SYN) to the
host with a **partial/offload** checksum — the value in the header is not valid
for its bytes. The incremental adjustment is still arithmetically right (it
preserves whatever relation the sender had), and the NIC's TX offload
recomputes the final value, which is why multi-megabyte transfers pass. The
alternative, `bpf_l4_csum_replace`/`bpf_l3_csum_replace`, understands offload
state and would remove the implicit dependency; it is not used yet.

## 8. ICMP

ICMP has no ports. Echo messages carry a 16-bit **identifier** that the peer
copies verbatim into its reply, so the datapath treats it as the port the
session tables key on:

- A request's identifier sits where a flow's source port would (`src_port`), a
  reply's where the destination port would (`dst_port`).
- On the way out the identifier is replaced by a value from the **same**
  `SNAT_IPLIST` counter TCP/UDP use — one 16-bit space that is unique per
  egress address, exactly like conntrack.
- The original identifier is recorded in `sbx_port` and restored on the way in.

Only echo request/reply are translated. ICMP **error** messages (destination
unreachable, TTL exceeded) refer to a flow they embed in their payload; those
are passed through untouched and are not yet supported.

## 9. Session lifecycle and expiry

### TCP

The state is the **client's** (the sandbox is always the side that opens), and
both classifiers move it:

| Event | From | To |
| --- | --- | --- |
| sandbox SYN (new session) | — | `SYN_SENT` |
| world SYN+ACK | `SYN_SENT` | `SYN_RECV` |
| sandbox ACK | `SYN_RECV` | `ESTABLISHED` |
| world FIN | `ESTABLISHED` | `CLOSE_WAIT` |
| world FIN | `FIN_WAIT` | `TIME_WAIT` |
| sandbox FIN | `ESTABLISHED` | `FIN_WAIT` |
| sandbox FIN | `CLOSE_WAIT` | `LAST_ACK` |
| world ACK | `LAST_ACK` | `CLOSE` |
| RST either side | any | `CLOSE` |

Retransmitted SYNs keep a handshake where it is; a SYN on a session that had
progressed past the handshake starts the cycle over on the same tuple.

### UDP and ICMP

- UDP starts in `UDP_UNREPLIED` and becomes `UDP_REPLIED` on the first
  returning datagram.
- ICMP echo has one state, `ICMP_PENDING`; the reply changes nothing.

### Expiry (userspace, every 5 s)

A thread in the daemon walks `EGRESS_SESSION`, and for each entry older than
its state allows, removes **both** halves. The ingress key is rebuilt from the
egress one: `{peer, peer_port → egress_ip, snat_port}`.

| State | Timeout |
| --- | --- |
| TCP ESTABLISHED | 3 h |
| TCP SYN_SENT / SYN_RECV / CLOSE_WAIT | 1 min |
| TCP FIN_WAIT / TIME_WAIT | 2 min |
| TCP LAST_ACK | 30 s |
| TCP CLOSE | 10 s |
| UDP unreplied / replied | 30 s / 180 s |
| ICMP | 30 s |

Two implementation notes:

- **Never delete while iterating.** aya's iterator asks the kernel for the key
  after the last one it returned (`bpf_map_get_next_key(prev)`), and for a key
  that is no longer in the map the kernel restarts from the first element. A
  deletion mid-pass can send the sweep back to the beginning. Expired keys are
  collected into a `Vec` first, then removed in a second pass.
- The daemon reads `CLOCK_MONOTONIC`, the same clock `bpf_ktime_get_ns` uses;
  no conversion is needed.

## 10. ARP responder — `sbxd_arp`

The sandbox ARPs for `169.254.0.1` like any host would. The program sees the
request on the veth's ingress hook, rewrites it into a reply (swapped
sender/target hardware and protocol addresses, opcode 2), and redirects it back
out the same veth. `sbx0` never has to receive anything.

## 11. Debugging

- **Frame log.** `sbxd_from_sandbox` copies a 48-byte `FrameEvent` summary into
  the `FRAMES` ring buffer *after* translation, so a translated line shows the
  headers the frame actually leaves with (egress MAC, next-hop MAC, SNAT
  address and port). Untranslated frames look unchanged, by definition. The
  daemon drains it on a thread at a 200 lines/s budget.
- **Inspect the tables.** `bpftool map dump name EGRESS_SESSION` (and
  `INGRESS_SESSION`); decode `EgressSessionValue` as `u64 access_time |
  u16 snat_port (network order) | u8 state | 5 bytes pad`.
- **Wire truth.** `tcpdump -l -n -e -i wlo1 'host <peer>'` shows the
  post-rewrite frames.

## 12. Known gaps

- ICMP error messages are not translated (see §8).
- TTL is not decremented; the host's routing does not see these frames.
- No IPv6, no IP options (the parser requires `ip[0] == 0x45`), no fragments —
  a fragmented flow beyond the first fragment will not match.
- The `SNAT_IPLIST` read-modify-write is not atomic. `bpf_spin_lock` on a map
  value needs BTF describing the value, and the object carries none; until
  that lands, two CPUs can hand out the same port.
- One egress interface per daemon; `EGRESS_IFINDEX` and both MACs are baked in.
- The sandbox is assumed to be the client: connections are only translated
  when the sandbox opens them, which is also what the TCP state machine
  assumes.

## 13. Verifier notes (for the next person editing the datapath)

- The BPF stack is 512 bytes and a struct passed **by reference** into a
  non-inlined subprogram is copied onto it. Passing `&Flow` down the call chain
  overflowed it (`R11 is invalid`); the fixes were scalar-only helper
  arguments and `#[inline(always)]` on the small `flow`/`csum`/`skb` helpers.
- Unbounded-looking loops are rejected (`the sequence of 8193 jumps is too
  complex`). The checksum fold is two unconditional rounds, not a loop.
- `bpf_skb_load_bytes` needs a **constant** size; aya's `load_bytes` with a
  runtime length fails verification. `skb::load` keeps the size constant.

## 14. Source map

| File | Contents |
| --- | --- |
| `sbxd/src/net.rs` | Default route, gateway MAC via ARP probe, egress MAC/address |
| `sbxd/src/ebpf.rs` | Object loading, global overrides, `SNAT_IPLIST` seed, attach |
| `sbxd/src/session.rs` | Userspace mirrors, expiry sweep |
| `sbxd-ebpf/src/consts.rs` | Protocol numbers, TCP flags, fixed MACs |
| `sbxd-ebpf/src/skb.rs` | Constant-size `bpf_skb_load_bytes` wrapper |
| `sbxd-ebpf/src/csum.rs` | RFC 1071 fold, RFC 1624 replace |
| `sbxd-ebpf/src/flow.rs` | IPv4/TCP/UDP/ICMP parsing and rewriting |
| `sbxd-ebpf/src/session.rs` | Keys, values, state machine |
| `sbxd-ebpf/src/snat.rs` | `SNAT_IPLIST` and the port range |
| `sbxd-ebpf/src/from_sandbox.rs` | Egress translation and frame log |
| `sbxd-ebpf/src/from_world.rs` | Ingress translation |
| `sbxd-ebpf/src/arp.rs` | Gateway ARP responder |
