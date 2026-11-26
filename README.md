# sbx-demo

用 Rust 写的 gVisor 沙箱管理器：一个常驻 daemon (`sbxd`) 管理 `runsc` 沙箱的生命周期，
一个 CLI (`sbx`) 与之通信，网络转发由自研的 TC eBPF 程序完成。

```
sbx (CLI) ──unix socket──▶ sbxd ──▶ runsc (gVisor, --network=sandbox)
                             │
                             └──▶ sbxd-ebpf: TC 分类器，SNAT / DNAT / 会话表 / ARP 应答
```

## 组成

| Crate | 说明 |
| --- | --- |
| `sbxd` | daemon：沙箱创建/删除、netns 与 veth 配置、bundle 生成、eBPF 加载与会话过期 |
| `sbx-cli` | `sbx` 命令行客户端 |
| `sbx-proto` | CLI 与 daemon 之间的请求/响应类型 |
| `sbxd-ebpf` | eBPF 数据面（独立 workspace，只编译到 `bpfel-unknown-none`） |

## 网络设计要点

每个沙箱一个 netns + 一对 veth，协议栈在 gVisor sentry 里。所有沙箱**刻意共用**
同一个地址 `169.254.0.21/32` 和同一个 MAC `02:53:42:58:00:21`，靠 veth 索引而不是
IP 区分会话。宿主上不装任何 iptables/nftables 规则：

- 出向 `from_sandbox`：SNAT，建会话，`bpf_redirect` 直接发出出口网卡；
- 入向 `from_world`：查会话反查沙箱，还原地址与端口，redirect 回对应 veth；
- `arp`：应答网关 `169.254.0.1` 的 ARP；
- 会话带 TCP/UDP/ICMP 状态，用户态线程每 5 秒按状态期限（ESTABLISHED 3h → CLOSE 10s）
  两侧同时清理。

完整设计见 [docs/ebpf-datapath.zh-CN.md](docs/ebpf-datapath.zh-CN.md)（英文版
[docs/ebpf-datapath.md](docs/ebpf-datapath.md)），载体与地址规划见
[docs/network-architecture.md](docs/network-architecture.md)。

## 构建

需要 Rust nightly 之外的常规工具链、`bpf-linker` 与 `llvm`（eBPF 目标）：

```bash
cargo install bpf-linker
cargo build --release
```

eBPF 目标单独构建：

```bash
cd sbxd-ebpf
cargo build --release --target bpfel-unknown-none -Z build-std=core
```

`sbxd/build.rs` 负责在编译 daemon 时把 eBPF 对象一起编出来。

## 运行

需要 root（加载 eBPF、创建 netns、运行 `runsc`）：

```bash
sudo ./target/release/sbxd --no-gpu &
sudo ./target/release/sbx new demo1 --bundle /opt/gvisor/bundles/base
sudo ./target/release/sbx run demo1 -- ping -c 2 1.1.1.1
sudo ./target/release/sbx ls
sudo ./target/release/sbx rm demo1
```

调试数据面：

```bash
bpftool map dump name EGRESS_SESSION
bpftool map dump name INGRESS_SESSION
```

## 已知边界

ICMP 只翻译 echo request/reply（差错报文未处理）；不递减 TTL；不支持 IPv6、IP 选项与
分片；SNAT 端口计数器非原子；单个出口网卡。详见文档 §12。
