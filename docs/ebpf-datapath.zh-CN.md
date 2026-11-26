# eBPF 数据面：gVisor 沙箱的网络转发实现

本文描述 `sbxd` 如何用 eBPF 在沙箱和外部网络之间转发报文，内容包括拓扑、程序与挂载点、map 结构与布局、两个方向的地址改写、会话生命周期，以及尚未实现的边界。

## 1. 拓扑

每个沙箱以 gVisor（`runsc`）运行在独立的网络命名空间里，通过一对 veth 与宿主相连：宿主侧命名为 `v-<id>`，沙箱侧为 `eth0`。

所有沙箱的配置刻意完全一致：

| 属性 | 取值 | 统一取值的理由 |
| --- | --- | --- |
| 沙箱地址 | `169.254.0.21/32` | 区分流靠数据面，不靠地址 |
| 沙箱 MAC | `02:53:42:58:00:21` | 同上 |
| 默认网关 | `169.254.0.1` | 宿主上的 dummy 设备 `sbx0` |
| 网关 MAC | `02:53:42:58:00:01` | 由 ARP 应答程序提供 |

```
        沙箱 netns                         宿主                          外部
 ┌──────────────────────┐        ┌──────────────────────────────┐
 │  eth0                │  veth  │  v-<id>          wlo1        │
 │  169.254.0.21/32  ───┼────────┼──▶ [TC ingress] ─────────────┼──▶ 下一跳
 │  gw 169.254.0.1      │        │      from_sandbox             │      (路由器)
 │  └─ ARP → sbxd_arp   │        │      arp                      │
 │                      │        │                               │
 │                      │        │  sbx0 (dummy, 169.254.0.1)    │
 │                      │        │                               │
 │   回程               │        │  [wlo1 的 TC ingress]         │
 │   ◀──────────────────┼────────┼── from_world (redirect)       │◀── 回包
 └──────────────────────┘        └──────────────────────────────┘
```

由于地址和 MAC 全部共享，**五元组本身不能唯一标识一个沙箱**。会话表仍然以五元组为键，在会产生歧义的地方把 veth 索引加进 key（见 `EgressSessionKey`）。

## 2. 为什么用 TC eBPF 而不是 iptables/nftables

- **流状态在数据面自己手里。** 两个方向各有一张翻译表，daemon 随时可以直接读（`bpftool map dump`），不存在 conntrack 里另一份"真相"。
- **一次 redirect，不进宿主协议栈。** 改写后的帧用 `bpf_redirect` 从 veth 直接送到出口网卡，宿主路由表、netfilter、`ip_forward` 都不在路径上。
- **规模。** 会话表是 `BPF_F_NO_PREALLOC` 的哈希表，上限一百万条，在没有条目之前不占内存。
- **沙箱保留自己的协议栈。** 命名空间里唯一的 IP 栈仍是 gVisor，沙箱内部不需要理解 NAT。

## 3. 程序与挂载点

三个程序都是 TC 分类器（`sched_cls`），挂在 **ingress** 钩子上。

| 程序 | 挂载点 | 职责 |
| --- | --- | --- |
| `sbxd_from_sandbox` | 每个 `v-<id>` 的 TC ingress | SNAT、建会话、redirect 到出口网卡 |
| `sbxd_arp` | 每个 `v-<id>` 的 TC ingress | 应答对 `169.254.0.1` 的 ARP |
| `sbxd_from_world` | 出口网卡（`wlo1`）的 TC ingress | 反向 NAT、redirect 进所属 veth |

`sbxd_from_sandbox` 必须挂在 `sbxd_arp` **之前**：同一钩子上的分类器按挂载顺序执行，而 ARP 应答程序会 redirect 它处理的帧，挂在它后面的程序将永远看不到这些帧。

返回码的含义：

| 返回值 | 含义 | 用途 |
| --- | --- | --- |
| `TC_ACT_REDIRECT` | 帧被 `bpf_redirect` 消费 | 已翻译的帧 |
| `TC_ACT_UNSPEC` | 交给同钩子的下一个分类器，再进宿主协议栈 | 不归本数据面管的帧 |
| `TC_ACT_SHOT` | 丢弃 | 游离报文、表满、改写失败 |

用 `TC_ACT_UNSPEC` 而不是 `TC_ACT_OK`，是为了让非 TCP/UDP 的帧继续落到后面的 ARP 应答程序。

链接是 TCX（由 fd 持有），`Datapath` 被 drop 时全部程序随之卸载——数据面的生命周期与 daemon 完全一致。

### 加载期常量

daemon 在程序被校验之前解析一次、以 aya `Global<T>` 静态变量烧进 `.rodata`：

| 符号 | 来源 | 使用方 |
| --- | --- | --- |
| `NEXT_HOP_MAC` | UDP 探测触发 ARP 后读 `/proc/net/arp` | 改写后帧的目的 MAC |
| `EGRESS_MAC` | `/sys/class/net/<if>/address` | 改写后帧的源 MAC |
| `EGRESS_IFINDEX` | `if_nametoindex` | `bpf_redirect` 的目标 |
| `SANDBOX_IP` | daemon 配置（`169.254.0.21`） | 回包改写后的目的地址 |

源端口计数器和出口地址放在 map 里而不是常量里，因为计数器必须运行期变化：`SNAT_IPLIST` 是一个长度为 1 的 `Array<SnatEntry { ip: [u8; 4], current_port: u16 }>`，由用户态在加载时写入出口地址和端口 `30000`。

## 4. Map

| Map | 类型 | Key | Value | 上限 |
| --- | --- | --- | --- | --- |
| `SNAT_IPLIST` | `Array` | `u32`（只有 0） | `SnatEntry`，6 字节 | 1 |
| `INGRESS_SESSION` | `HashMap`，`BPF_F_NO_PREALLOC` | `SessionKey`，14 字节 | `IngressSessionValue`，24 字节 | 1 048 576 |
| `EGRESS_SESSION` | `HashMap`，`BPF_F_NO_PREALLOC` | `EgressSessionKey`，20 字节 | `EgressSessionValue`，16 字节 | 1 048 576 |
| `FRAMES` | `RingBuf` | — | `FrameEvent`，48 字节 | 256 KiB |

```text
SessionKey           src_ip[4] dst_ip[4] src_port u16 dst_port u16 protocol u8 _pad u8
IngressSessionValue  access_time u64 | sbx_mac[6] sbx_port u16 | veth_ifindex u32 | state u8 _pad[3]
EgressSessionKey     veth_ifindex u32 | flow: SessionKey | _pad u16
EgressSessionValue   access_time u64 | snat_port u16 | state u8 _pad[5]
```

所有结构体都是 `repr(C)`，显式补齐填充，并且在 eBPF crate 和用户态镜像两侧都写了 `const _: () = assert!(size_of::<T>() == N)`——布局一旦漂移，是编译失败而不是 map 数据错乱。

key 和 value 里的端口都是**网络字节序**，与线上完全一致，因此可以直接从报文构造 key，不需要换字节序。

### 为什么是两张会话表

- `INGRESS_SESSION` 以**回包方向**的五元组为键：`{peer, peer_port, egress_ip, snat_port, proto}`。回包用它自己的头部查一次就能找回沙箱。
- `EGRESS_SESSION` 以**沙箱方向**的五元组加 veth 索引为键：`{veth_ifindex, {sandbox_ip, sandbox_port, peer, peer_port, proto}}`。它保证重传的 SYN 复用已经分配过的端口。veth 索引是必需的，因为所有沙箱共享地址和 MAC。

## 5. 出方向 —— `sbxd_from_sandbox`

报文由共享的 `flow::ipv4_flow` 解析，只接受无选项的 IPv4、承载 TCP、UDP 或 ICMP echo（见 §8），其余一律原样放行。

1. 从 `__sk_buff.ifindex` 读取 veth 索引。
2. 从 `SNAT_IPLIST[0].ip` 读取出口地址。
3. 构造 `EgressSessionKey`，查 `EGRESS_SESSION`：
   - 未命中且是**没有 SYN 的 TCP 段** → **丢弃**。既不属于任何会话、又不打开新会话的段是游离报文，不能让它凭空建会话。
   - 未命中 → 从 `SNAT_IPLIST` 取下一个端口（回绕：`(p + 1) % 30000 + 30000`），插入 `EgressSessionValue { access_time, snat_port, state = initial_state(proto) }`。
   - 命中 → 复用记录的 `snat_port`。
4. 改写链路头：源 = `EGRESS_MAC`，目的 = `NEXT_HOP_MAC`。
5. 源 IP 改为出口地址并重算 IPv4 头校验和；对地址和端口增量修正传输层校验和；把 SNAT 端口（或 ICMP identifier）写到 `flow.src_field()`。
6. 构造回程 key `{src: dst_ip, src_port: dst_port, dst: egress_ip, dst_port: snat_port}`。
7. 新会话：插入 `IngressSessionValue { access_time, sbx_mac = SANDBOX_MAC, sbx_port = 原始源端口/identifier, veth_ifindex, state }`。已有会话：用 `sandbox_packet()` 推进状态，并刷新两张表的 `access_time`。
8. `bpf_redirect(EGRESS_IFINDEX, 0)`；成功 → `TC_ACT_REDIRECT`，失败 → `TC_ACT_SHOT`。

这里从不删除条目。结束的流会留在 `TIME_WAIT`/`CLOSE` 状态，让迟到的段仍能翻译；清理交给用户态的定时任务（§9）。

## 6. 入方向 —— `sbxd_from_world`

挂在出口网卡的 ingress 钩子上，因此能看到**所有**入方向报文，其中大部分属于宿主自己。

1. 解析；ICMP 中只考虑 echo **回复**（`type 0`）。
2. 用报文自身的五元组查 `INGRESS_SESSION`：
   - 未命中 → `TC_ACT_UNSPEC`，报文原样交给宿主协议栈。
3. 在后续任何 helper 调用之前，先把条目的 `veth_ifindex`、`sbx_mac`、`sbx_port` 和当前状态拷贝出来。
4. 改写链路头：源 = `GATEWAY_MAC`（就像从沙箱的网关发出），目的 = 沙箱的 MAC。
5. 目的地址改为 `SANDBOX_IP`，修正校验和，把 `sbx_port` 写到 `flow.dst_field()`。
6. 构造对应的 `EgressSessionKey`（流方向反转，用沙箱地址和端口替换出口地址和 SNAT 端口），用 `world_packet()` 推进状态，**两张表**的 `access_time` 和状态一起刷新。
7. `bpf_redirect(veth_ifindex, 0)`。

## 7. 校验和

- **IPv4 头**：把校验和字段清零后，对 20 字节头部整体重算（`flow::set_ip`）。这里也可以做增量修正，但地址改写时头部本来就已经读出到栈上，整体重算更直接。
- **TCP/UDP**：增量修正，RFC 1624 公式 3——伪首部里变化的两段地址 16 位字，加上端口字。payload 从不读取。
  - UDP 校验和为 `0`（发送方没算）保持 `0`。
  - 增量计算得到 `0` 的 UDP 校验和存为 `0xffff`。
- **ICMP echo**：没有伪首部，只替换 identifier 一个 16 位字。

一个需要知道的现象：gVisor 交给宿主的 TCP 段（SYN 除外）头部是**部分/offload** 校验和——字段里的值与报文字节并不自洽。增量修正仍然是算术上正确的（它保持发送方建立的任何关系不变），最终值由网卡 TX offload 重算，所以数 MB 的传输能正常完成。另一种做法 `bpf_l4_csum_replace`/`bpf_l3_csum_replace` 能感知 offload 状态，可以去掉这个隐式依赖，目前尚未采用。

## 8. ICMP

ICMP 没有端口。echo 报文携带一个 16 位的 **identifier**，对端会原样复制进回复，因此数据面把它当作会话表键里的"端口"：

- 请求的 identifier 放在流里源端口的位置（`src_port`），回复的放在目的端口的位置（`dst_port`）。
- 出方向把 identifier 换成 **同一个** `SNAT_IPLIST` 计数器分配的值——和 TCP/UDP 共用同一个 16 位空间，对出口地址唯一，这正是 conntrack 的做法。
- 原 identifier 记入 `sbx_port`，入方向还原。

只翻译 echo request/reply。ICMP **差错报文**（目的不可达、TTL 超时等）的身份藏在 payload 内嵌的原始 IP 头里，目前原样放行，尚未支持。

## 9. 会话生命周期与过期

### TCP

状态是**客户端视角**的（沙箱永远是发起方），两个分类器共同推进：

| 事件 | 原状态 | 新状态 |
| --- | --- | --- |
| 沙箱 SYN（新会话） | — | `SYN_SENT` |
| 外部 SYN+ACK | `SYN_SENT` | `SYN_RECV` |
| 沙箱 ACK | `SYN_RECV` | `ESTABLISHED` |
| 外部 FIN | `ESTABLISHED` | `CLOSE_WAIT` |
| 外部 FIN | `FIN_WAIT` | `TIME_WAIT` |
| 沙箱 FIN | `ESTABLISHED` | `FIN_WAIT` |
| 沙箱 FIN | `CLOSE_WAIT` | `LAST_ACK` |
| 外部 ACK | `LAST_ACK` | `CLOSE` |
| 任一侧 RST | 任意 | `CLOSE` |

重传的 SYN 不改变握手中的状态；握手完成之后同一五元组上的新 SYN 会把会话重置回握手起点。

### UDP 与 ICMP

- UDP 初始为 `UDP_UNREPLIED`，收到第一个回包变 `UDP_REPLIED`。
- ICMP echo 只有一个状态 `ICMP_PENDING`，回包不改变它。

### 过期（用户态，每 5 秒）

daemon 里一个线程遍历 `EGRESS_SESSION`，超过所在状态时限的条目**两侧同时删除**。ingress key 由 egress key 重建：`{peer, peer_port → egress_ip, snat_port}`。

| 状态 | 超时 |
| --- | --- |
| TCP ESTABLISHED | 3 小时 |
| TCP SYN_SENT / SYN_RECV / CLOSE_WAIT | 1 分钟 |
| TCP FIN_WAIT / TIME_WAIT | 2 分钟 |
| TCP LAST_ACK | 30 秒 |
| TCP CLOSE | 10 秒 |
| UDP 未回复 / 已回复 | 30 秒 / 180 秒 |
| ICMP | 30 秒 |

两个实现要点：

- **不能在遍历中删除。** aya 的迭代器向内核请求"上一个 key 之后的下一个"（`bpf_map_get_next_key(prev)`），而 key 已不在表中时内核会**从第一个元素重新开始**，边遍历边删会让扫描不断回到起点。实现是先把过期 key 收进 `Vec`，遍历结束后再统一删除。
- daemon 读 `CLOCK_MONOTONIC`，与 `bpf_ktime_get_ns` 是同一个时钟，不需要换算。

## 10. ARP 应答 —— `sbxd_arp`

沙箱像任何主机一样对 `169.254.0.1` 发 ARP。程序在 veth 的 ingress 钩子上看到请求，把它改写成应答（交换 sender/target 的硬件地址和协议地址，opcode 改为 2），再 redirect 回同一个 veth。`sbx0` 本身从不需要收到任何东西。

## 11. 调试

- **帧日志。** `sbxd_from_sandbox` 在翻译**之后**把 48 字节的 `FrameEvent` 摘要写进 `FRAMES` ring buffer，所以被翻译的行显示的是帧真正离开时的头部（出口 MAC、下一跳 MAC、SNAT 地址和端口）；未被翻译的帧按定义保持原样。daemon 在独立线程里读取，限速 200 行/秒。
- **查表。** `bpftool map dump name EGRESS_SESSION`（以及 `INGRESS_SESSION`）；`EgressSessionValue` 的解析是 `u64 access_time | u16 snat_port（网络序） | u8 state | 5 字节 padding`。
- **线上事实。** `tcpdump -l -n -e -i wlo1 'host <peer>'` 看到的是改写后的帧。

## 12. 已知边界

- ICMP 差错报文不翻译（见 §8）。
- 不递减 TTL；宿主路由看不到这些帧。
- 不支持 IPv6、IP 选项（解析器要求 `ip[0] == 0x45`）和分片——首片之后的分片报文匹配不到会话。
- `SNAT_IPLIST` 的读-改-写不是原子的。map value 上的 `bpf_spin_lock` 需要描述该 value 的 BTF，而当前编译产物没有 BTF；在补上之前，两个 CPU 可能发出同一个端口。
- 每个 daemon 只支持一个出口网卡；`EGRESS_IFINDEX` 和两个 MAC 都是烧录常量。
- 假定沙箱是客户端：只有沙箱主动发起的连接会被翻译，TCP 状态机也基于这个假设。

## 13. 给下一个改数据面的人：验证器笔记

- BPF 栈是 512 字节，**按引用**传入未内联子程序的结构体会被复制到栈上。把 `&Flow` 沿调用链传下去会直接撑爆（`R11 is invalid`）；解决办法是 helper 只收标量参数，以及给 `flow`/`csum`/`skb` 的小函数加 `#[inline(always)]`。
- 看起来无界的循环会被拒绝（`the sequence of 8193 jumps is too complex`）。校验和的折叠是两轮无条件计算，不是循环。
- `bpf_skb_load_bytes` 的长度必须是**常量**；aya 的 `load_bytes` 用运行期长度会过不了验证。`skb::load` 保证长度是常量。

## 14. 源码索引

| 文件 | 内容 |
| --- | --- |
| `sbxd/src/net.rs` | 默认路由、ARP 探测取网关 MAC、出口 MAC/地址 |
| `sbxd/src/ebpf.rs` | 加载对象、覆盖全局常量、写入 `SNAT_IPLIST`、挂载 |
| `sbxd/src/session.rs` | 用户态镜像结构、过期清理 |
| `sbxd-ebpf/src/consts.rs` | 协议号、TCP 标志、固定 MAC |
| `sbxd-ebpf/src/skb.rs` | 常量长度的 `bpf_skb_load_bytes` 封装 |
| `sbxd-ebpf/src/csum.rs` | RFC 1071 折叠、RFC 1624 替换 |
| `sbxd-ebpf/src/flow.rs` | IPv4/TCP/UDP/ICMP 解析与改写 |
| `sbxd-ebpf/src/session.rs` | key、value、状态机 |
| `sbxd-ebpf/src/snat.rs` | `SNAT_IPLIST` 与端口范围 |
| `sbxd-ebpf/src/from_sandbox.rs` | 出方向翻译与帧日志 |
| `sbxd-ebpf/src/from_world.rs` | 入方向翻译 |
| `sbxd-ebpf/src/arp.rs` | 网关 ARP 应答 |
