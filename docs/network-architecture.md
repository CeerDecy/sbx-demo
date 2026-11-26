# 沙箱网络架构

> 记录 **当前代码实际做到的事**（sbxd 模块化之后，2026-11-25）。
> 转发面（eBPF）的设计与实现见 [ebpf-datapath.zh-CN.md](ebpf-datapath.zh-CN.md)（英文版 [ebpf-datapath.md](ebpf-datapath.md)），§7 指向那里。

## 1. 一句话

每个沙箱跑在独立的 network namespace 里，但 TCP/IP **不在宿主内核**：gVisor sentry 的 netstack 持有 `eth0` 和它的地址。宿主只看到一个 veth 口和裸以太帧。所有沙箱共用同一个地址 `169.254.0.21/32` 与同一个 MAC `02:53:42:58:00:21`，默认网关 `169.254.0.1` 的 ARP 应答与转发全部留给 eBPF。

## 2. 拓扑

```
                  ┌──────────────────────── 宿主 netns ────────────────────────┐
                  │                                                             │
  eBPF 数据面     │   v-<id>   veth 宿主端：内核随机 MAC，无 IPv4               │
  （待实现）◄─────┼───  ▲                                                       │
                  │      │  裸以太帧（src MAC 02:53:42:58:00:21）               │
                  │   ┌──┴───────┐                                              │
                  │   │  sbx0    │   dummy L2，MAC 02:53:42:58:00:01，无地址     │
                  │   └──────────┘                                              │
                  └──────┬──────────────────────────────────────────────────────┘
                         │ veth pair（内核内部搬运，无用户态参与）
                  ┌──────▼────────── netns sbx-<id> ─────────┐
                  │   eth0   MAC 02:53:42:58:00:21，无 IPv4   │
                  │     ▲  AF_PACKET（FDBasedLink 的出口）    │
                  └─────┼────────────────────────────────────┘
                        │
                ┌───────▼───────── gVisor sentry ──────────┐
                │  netstack                                │
                │    eth0  169.254.0.21/32 scope global    │
                │    default via 169.254.0.1 dev eth0      │
                │             onlink, scope link           │
                └──────────────────────────────────────────┘
```

## 3. 组件

### 3.1 `sbx0`：网关侧 L2 设备

daemon 每次启动时由 `net::ensure_gateway_link()` 保证存在：

| 属性 | 值 |
|---|---|
| 类型 | `dummy` |
| 名称 | `sbx0`（常量 `GATEWAY_LINK`） |
| MAC | `02:53:42:58:00:01`（常量 `GATEWAY_MAC`），本地管理 + 单播 |
| 地址 | 无 IPv4、无 IPv6（`net.ipv6.conf.sbx0.disable_ipv6=1`，否则 up 时内核会自动加 link-local） |
| 状态 | `UP,LOWER_UP`，无对端 |

它没有对端，本身不承载业务流量。存在意义是给 eBPF 一个**稳定、名字和 MAC 固定**的 L2 端点；具体怎么用（redirect 目标、网关身份、镜像口）由数据面决定。

### 3.2 veth pair：沙箱的载体

每创建一个沙箱，`net::attach_interface()` 执行一次：

```text
ip link add v-<id> type veth peer name eth0 netns sbx-<id>
ip link set v-<id> up
ip -n sbx-<id> link set lo up
ip -n sbx-<id> link set eth0 address 02:53:42:58:00:21
ip -n sbx-<id> addr add 169.254.0.21/32 dev eth0
ip -n sbx-<id> link set eth0 up
ip -n sbx-<id> route add default via 169.254.0.1 dev eth0 onlink
```

- 宿主端 `v-<id>` 的 MAC 由内核随机分配（观察值如 `7e:c9:fe:57:25:75`），**没有 IP**。它只是帧的出入口，不参与路由。
- 对端直接命名为 `eth0` 并落入沙箱专属 netns；宿主机根 netns 里看不到它。
- `onlink` 是必须的：eth0 上只有 `/32`，`169.254.0.1` 不在任何直连网段里，不加 `onlink` 路由会被拒绝。

### 3.3 netns：只做设备的容器

netns `sbx-<id>` 存在的唯一理由有两个：

1. gVisor 拒绝在 root netns 里开网络（`cannot run with network enabled in root network namespace`）；
2. 给 netstack 提供一个真实的 `eth0` 设备去挂 `AF_PACKET`。

沙箱运行期间 netns 里**没有任何 IPv4 地址**——地址会被 runsc 搬走，见 §5.3。

### 3.4 netstack：真正的协议栈

runsc 以 `--network=sandbox` 启动，sentry 内部用 gVisor netstack：

- eth0 的地址、路由、ARP 邻居表、TCP 状态、重传、分片全部在 sentry 的用户态代码里；
- 与外界交换的是**完整以太帧**：netstack 通过 `FDBasedLink` 在 netns 的 `eth0` 上开 `AF_PACKET`（`PACKET_VNET_HDR`），把帧写进 veth、从 veth 读帧；
- 宿主机内核协议栈完全不参与：没有 socket、没有 conntrack、没有 neighbour 表项属于沙箱。

这也是为什么不能用 XDP 方案：`runsc release-20261116.0` 的发布二进制没有编译 XDP 支持（需 `--define=gotags=xdp` 自行构建）。

## 4. 地址与 MAC 规划

| 项 | 值 | 范围 |
|---|---|---|
| 沙箱 eth0 地址 | `169.254.0.21/32` | 所有沙箱相同 |
| 沙箱 eth0 MAC | `02:53:42:58:00:21` | 所有沙箱相同；`02`=本地管理+单播，`53 42 58`=ASCII "SBX"，末字节对齐 `.21` |
| 默认网关 | `169.254.0.1` | 硬编码；ARP 由 eBPF 应答 |
| 宿主 veth `v-<id>` | 内核随机 MAC，无 IP | 每沙箱不同（名字不同） |
| 网关设备 `sbx0` | `02:53:42:58:00:01`，无地址 | 全局唯一 |
| MTU | 1500 | 继承内核默认 |

地址共享是刻意的：沙箱之间不需要互通，宿主也没有「按 IP 区分沙箱」的需求。**代价**是宿主侧任何会话表、限速、审计都必须以 `v-<id>` 的 ifindex（或端口）为键，不能用源 IP。

## 5. 数据路径

### 5.1 出向：沙箱 → 网线

```
沙箱进程 write()
  → sentry netstack：TCP/UDP、IP、路由到 169.254.0.1
  → 邻居解析：ARP 请求 169.254.0.1（当前无人应答 → 发包失败）
  → netstack 组装以太帧（src 02:53:42:58:00:21 / 169.254.0.21）
  → FDBasedLink 写入 netns eth0 的 AF_PACKET
  → 内核 veth 转发：netns eth0 → 宿主 v-<id>
  → 【eBPF 挂载点：v-<id> 的 tc/XDP】
```

到达宿主时已经是**完整以太帧**，没有宿主 socket 参与，也没有 conntrack 条目。

### 5.2 入向：网线 → 沙箱

```
宿主 v-<id> 收到帧（eBPF redirect 或对端写入）
  → 内核 veth：v-<id> → netns eth0
  → netns eth0 上的 AF_PACKET 被 sentry 读出
  → netstack 校验、查会话、投递给沙箱 socket
```

### 5.3 地址迁移：为什么 netns 里看不到 IP

runsc 启动时执行 `createInterfacesAndRoutesFromNS`：把 netns 里 eth0 的地址、路由、MAC 读出来，装进 netstack，然后 `removeLinkAddresses` 把 IPv4 地址从设备上删掉。于是：

```text
# 宿主视角（netns 里）
2: eth0@if79: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    link/ether 02:53:42:58:00:21          ← MAC 留在设备上，也复制进了 netstack
    （没有 inet）

# 沙箱视角（netstack 里）
2: eth0: <MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    link/ether 02:53:42:58:00:21
    inet 169.254.0.21/32 scope global dynamic eth0
    default via 169.254.0.1 dev eth0 scope link
```

`sbx ls` 的 ADDRESS 列恒为 `none` 就是这个原因——它读的是 netns（`ip netns exec ... addr show eth0`），而地址已经在 netstack 里。属于已知的显示缺陷，不影响功能。

### 5.4 当前连通性

零规则、零转发：

- 沙箱 ↔ 沙箱：不通（同一地址，且无二层路径）
- 沙箱 ↔ 宿主：不通（`v-<id>` 无 IP，宿主协议栈看不到沙箱 IP）
- 沙箱 ↔ 内网/公网：不通（默认路由的下一跳 ARP 无人应答）
- 宿主机上**没有任何** sbxd 安装的 iptables / ipvs 规则

eBPF 应答 `169.254.0.1` 的 ARP 并接管转发之后，这三条才会变成设计中的可达性。

## 6. 生命周期

### 6.1 创建（`Request::New`）

1. 校验 id（小写字母/数字/短横线，≤31 字节）、bundle 里必须有 `rootfs/`；
2. 拿 lifecycle 锁，检查 netns 与 runsc 里是否已存在同名沙箱；
3. 从索引池分配 index（见 §6.3），`next_index = index + 1`；
4. `ip netns add sbx-<id>`，随后是 §3.2 的一串 veth/地址/路由命令；
5. 准备私有 bundle：`bundles/sbx-<id>/` 从 base 拷一份（硬链接优先），写 `.base-bundle` 标记，改写 `config.json` 的网络命名空间路径与 init 进程；
6. `runsc --platform=systrap --network=sandbox run -detach -bundle <private> <id>`；
7. 记录 `SandboxRecord` 进 state，原子落盘。

任何一步失败，`Rollback` 的 `Drop` 会杀掉 runsc 沙箱、删 netns、回滚 index 与 state 条目。

### 6.2 删除（`Request::Rm`）

`runsc kill KILL` → 等 1 秒 → `runsc delete` → `ip netns del` → 从 state 移除并落盘。除存在性检查外都是 best-effort：残缺的沙箱也要能删掉。

### 6.3 索引池

`index` 是早期 `/31` 地址方案留下的**记账字段**，现在不参与地址分配（地址固定为 `.21`）。
`net::allocate_index()` 取 `1..=127` 中最小的空闲值，空闲集来自两处：`state.json` 里已记录的 index，以及宿主上带 IP 的 `v-*` 接口。

后者目前恒为空——宿主 veth 已经不再配 IP——所以实际上只有 state 在做约束。如果 `state.json` 丢失而沙箱还在运行，index 可能重复；因为地址共享，重复不会造成冲突，只是账目失真。

### 6.4 state.json

```json
{
  "next_index": 3,
  "entries": [
    {
      "id": "demo1",
      "bundle": "/opt/gvisor/bundles/sbx-demo1",
      "netns": "sbx-demo1",
      "veth": "v-demo1",
      "ident": "169.254.0.21",
      "index": 1
    }
  ]
}
```

由 `state::State` / `state::SandboxRecord` 序列化，写入走 `files::atomic_write`（同目录临时文件 + `rename`）。

## 7. eBPF 数据面

数据面已实现：SNAT / 反向 NAT、会话表、TCP/UDP/ICMP 状态与过期、网关 ARP 应答。
完整设计见 [ebpf-datapath.zh-CN.md](ebpf-datapath.zh-CN.md)。

## 8. 代码地图

| 模块 | 网络相关职责 |
|---|---|
| `sbxd/src/net.rs` | `sbx0` 的创建与 MAC/无地址保证；netns 建删；veth/地址/路由；索引池 |
| `sbxd/src/sandbox.rs` | 创建流程编排、`runsc run` 的参数（`--platform=systrap`、`--network=sandbox`）、`Rollback` |
| `sbxd/src/daemon.rs` | 启动时 `ensure_gateway_link()` 由 `main` 调用；请求分发 |
| `sbxd/src/config.rs` | `ident`（默认 `169.254.0.21`）等参数 |
| `sbxd/src/state.rs` | `SandboxRecord`：netns、veth、ident、index |
| `sbxd/src/bundle.rs` | 把 `config.json` 的网络命名空间指向 `/var/run/netns/sbx-<id>` |

常量集中在 `net.rs`：`SANDBOX_MAC`、`GATEWAY_LINK`、`GATEWAY_MAC`、`GATEWAY_ADDR`、`MAX_INDEX`。

## 9. 验证

```bash
sbx new d1
ip -n sbx-d1 -o link show eth0         # MAC 02:53:42:58:00:21，无 inet
sbx run d1 -- ip -4 addr show eth0      # 169.254.0.21/32（netstack 内）
sbx run d1 -- ip route                  # default via 169.254.0.1 ... onlink
ip -o link show v-d1                    # 宿主端 veth，随机 MAC，无 IP
ip -o link show sbx0                    # 02:53:42:58:00:01
sbx run d1 -- nc -w 2 169.254.0.1 80    # 当前应失败（ARP 无人应答）
iptables -S | grep -c sbx               # 0：daemon 不装任何规则
sbx rm d1
```

## 10. 已知限制

| 限制 | 说明 |
|---|---|
| 地址与 MAC 全沙箱共享 | 宿主侧不能用 IP 区分沙箱，只能用 veth ifindex；也意味着没有天然的防地址欺骗（同 MAC 同 IP，欺骗无意义但也无法靠地址做准入） |
| 协议栈在用户态 | 宿主的 `ss`、`conntrack`、`tcpdump -i any` 看不到沙箱 socket；抓包只能在 `v-<id>` 上看到以太帧 |
| 无 IPv6 | netns 里没有配置，`sbx0` 显式关闭 |
| 无 DNS / NAT / 入站 | 全部属于 eBPF 数据面的阶段边界 |
| `sbx ls` 地址显示 `none` | 读 netns 而非 netstack，见 §5.3 |
| index 池约束弱 | 见 §6.3 |
| 不支持 XDP 依赖的路径 | 发布版 runsc 未编译 XDP；netstack 模式不依赖它 |
