<h1 align="center">pMaker</h1>

<p align="center">
  <strong>Generate Pcap Easier Again.</strong>
</p>

<p align="center">
  用声明式文件构造可复现的离线流量样本，让验证流量像代码一样可读、可审、可回归。
</p>

<p align="center">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.25%2B-00ADD8?style=for-the-badge&logo=go&logoColor=white">
  <img alt="YAML" src="https://img.shields.io/badge/Config-YAML-CB171E?style=for-the-badge&logo=yaml&logoColor=white">
  <img alt="PCAP" src="https://img.shields.io/badge/Output-PCAP-7C3AED?style=for-the-badge">
  <img alt="CGO" src="https://img.shields.io/badge/CGO-disabled-16A34A?style=for-the-badge">
  <img alt="Offline" src="https://img.shields.io/badge/Network-offline_only-111827?style=for-the-badge">
</p>

---

```text
                         ┌─────────────────────┐
                         │    scenario.yaml    │
                         │ packets + flows DSL │
                         └──────────┬──────────┘
                                    │
                                    │ declarative traffic intent
                                    ▼
┌────────────────────────────────────────────────────────────────────┐
│                         pMaker pipeline                            │
│                                                                    │
│  ordered stack   ──▶  protocol linking  ──▶  deterministic pcap    │
│  eth/vlan/ip/...      checksum / length        timestamps / bytes  │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │       out.pcap      │
                         │ replay / inspect /  │
                         │ regression archive  │
                         └─────────────────────┘
```

## 一句话

**pMaker 是一个离线 pcap 构造器：用 YAML 描述协议栈和会话行为，输出确定性 `.pcap` 文件。**

它不抓包、不发包、不打开 raw socket，而是把 “临时造流量” 变成可以沉淀在仓库里的测试资产。

## 适合构造什么？

<table>
<tr>
<td width="50%">

### 封装 / 隧道

- 单层 VLAN / QinQ
- GRE 隧道
- 外层 / 内层 IPv4 / IPv6
- next-proto / EtherType 自动串接
- 显式覆盖协议字段制造解析断链

</td>
<td width="50%">

### TCP 会话

- 三次握手
- seq / ack 自动推导
- MSS 分段
- HTTP request / response
- FIN 四次挥手
- RST 关闭

</td>
</tr>
<tr>
<td width="50%">

### 网络层 / 传输层 / 应用层

- IPv4 / IPv6
- TCP
- UDP
- ICMPv4 / ICMPv6
- HTTP
- DNS
- ...

</td>
<td width="50%">

### 畸形 / 原始字节

- `payload_hex` 原始字节注入
- 非标准 next-protocol
- 手工 quote
- 为规避、解析异常、边界条件预留 escape hatch

</td>
</tr>
</table>

## 协议栈是“有序栈”，不是固定槽位

pMaker 的 packet 模型是从外到内排列的 `stack`：

```yaml
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - tcp:  { sport: 40000, dport: 80, flags: [SYN], seq: 1000 }
```

因此同一种模型可以表达：

```text
eth / ipv4 / tcp
eth / vlan / vlan / ipv4 / tcp
eth / ipv4 / gre / ipv4 / tcp
eth / ipv4 / udp / dns
eth / ipv4 / icmp
eth / ipv6 / icmpv6
```

这让 QinQ、GRE、隧道内层协议、重复封装都成为自然的一等能力，而不是后补的特殊 case。

## 自动串接协议字段

常规情况下，你只需要声明层顺序：

```text
eth → vlan → vlan → ipv4 → tcp
```

pMaker 会自动推导：

| 位置 | 自动处理 |
| --- | --- |
| Ethernet | EtherType |
| VLAN | inner type |
| IPv4 | protocol |
| GRE | protocol |
| TCP / UDP | checksum pseudo-header |

但如果测试目标就是“解析断链”或“非标准封装”，也可以显式覆盖：

```yaml
- vlan: { vid: 100, type: 0xffff }
```

## Flow：从应用脚本展开为 TCP 包序列

除了逐包写 stack，也可以描述一条有状态 TCP flow：

```yaml
flows:
  - name: http-flow
    stack:
      - eth:  { src: "00:00:00:00:00:01", dst: "00:00:00:00:00:02" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000, mss: 1460 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - http_request: { method: GET, url: /index.html }
      - from: dst
        stack:
          - http_response: { status: 200, body: "Hello from pMaker" }
```

展开结果概念上是：

```text
client                                             server
  │                                                  │
  │ ─────────────── SYN ───────────────────────────▶ │
  │ ◀──────────── SYN,ACK ────────────────────────── │
  │ ─────────────── ACK ───────────────────────────▶ │
  │ ───────── HTTP request ────────────────────────▶ │
  │ ◀────────────── ACK ──────────────────────────── │
  │ ◀──────── HTTP response ──────────────────────── │
  │ ─────────────── ACK ───────────────────────────▶ │
  │ ───────────── FIN/ACK ... ─────────────────────▶ │
```

自动维护：

- TCP flags
- seq / ack
- SYN 消耗序号
- FIN 消耗序号
- 纯 ACK 不消耗序号
- MSS 分段
- 多轮请求 / 响应

## 快速开始

### 构建

```bash
CGO_ENABLED=0 go build -o bin/pmaker ./cmd/pmaker
```

pMaker 使用纯 Go 的 `pcapgo` 写文件，无需 libpcap / CGO。

### 生成 pcap

```bash
./bin/pmaker gen -f examples/http_get.yaml -o out.pcap
```

### 校验 YAML

```bash
./bin/pmaker validate -f examples/qinq_gre.yaml
```

## YAML 约定

当前只支持 YAML 配置文件。

```yaml
link_type: ethernet
seed: 42
packets: []
flows: []
```

约定：

- `stack` 从外到内排列
- 每个 stack 元素是单键 map，例如 `- ipv4: {...}`
- 同类型层可以重复，例如 `vlan / vlan`
- next-protocol 默认自动推导，也可显式覆盖
- raw bytes 使用 `payload_hex: 0x...`
- 同一 scenario 应生成相同 pcap

## 测试

```bash
go test ./...
```

更新 golden pcap：

```bash
go test ./internal/scenario -run TestExamplesGolden -update
```

## 安全边界

pMaker 是离线 pcap 构造工具：

- 不主动发包
- 不打开 raw socket
- 不执行实时注入
- 默认不触碰网络接口

生成的 `.pcap` 可交给 `tcpreplay`、网络安全设备或分析工具使用。

如果未来增加实时注入能力，应放在独立且默认关闭的构建标签后，并显式提示权限要求。

## 项目定位

```text
不是流量黑盒生成器
而是可声明、可审查、可复现、可回归的 pcap 构造器
```