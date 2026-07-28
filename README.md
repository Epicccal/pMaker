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
  <img alt="Coverage" src="https://img.shields.io/badge/Coverage-Codecov-01B4B4?style=for-the-badge&logo=codecov&logoColor=white">
  <img alt="GoReport" src="https://img.shields.io/badge/Go_Report-A%2B-success?style=for-the-badge&logo=go&logoColor=white">
</p>

---

## 目录

- [一句话](#一句话)
- [快速开始](#快速开始)
- [核心数据流](#核心数据流)
- [适合构造什么](#适合构造什么)
- [有序层栈嵌套](#有序层栈嵌套)
- [Flow 状态维护](#flow-状态维护)
- [YAML 约定](#yaml-约定)
- [测试](#测试)
- [安全边界](#安全边界)
- [CI/CD](#cicd)

## 一句话

**pMaker 是一个离线 pcap 构造器：用 YAML 描述协议栈和会话行为，输出确定性 `.pcap` 文件。**

它不抓包、不发包、不打开 raw socket，而是把“临时造流量”变成可以沉淀在仓库里的测试资产。

## 快速开始

### 构建

```bash
CGO_ENABLED=0 go build -o bin/pmaker ./cmd/pmaker
```

pMaker 使用纯 Go 的 `pcapgo` 写文件，无需 libpcap / CGO。

### 生成 pcap

```bash
./bin/pmaker gen -f examples/http/get.yaml -o out.pcap
```

### 校验 YAML

```bash
./bin/pmaker validate -f examples/tunnel/qinq_gre.yaml
```

## 核心数据流

<details>
<summary>展开查看 pMaker pipeline</summary>

```text
                 ┌────────────────────────┐
                 │ scenario.yaml          │
                 │ packets + flows DSL    │
                 │ base_time / seed / ... │
                 └────────────┴───────────┘
                              │ parse + validate
                              │ field/path errors
                              ▼
  ┌───────────────────────────┬───────────────────────────┐
  │                    pMaker pipeline                    │
  │                                                       │
  │ scenario ──┬──> flows ──> plan ──> builder ──> writer │
  │            │                │                         │
  │            └────packets─────┘   bypass flows          │
  │                                                       │
  │ scenario : parse + validate                           │
  │ flows    : stateful TCP expand                        │
  │ plan     : merge packets + flows, sort by Time        │
  │ builder  : ordered stack -> gopacket, auto link       │
  │ writer   : pcapgo pure Go, deterministic bytes        │
  └───────────────────────────┴───────────────────────────┘
                              │
                              ▼
              ┌───────────────┬───────────────┐
              │ out.pcap                      │
              │ replay / inspect / regression │
              └───────────────────────────────┘
```

</details>

## 适合构造什么

pMaker 面向**授权环境下的离线流量验证**——把"造一个特定形状的包/流"这件事变成可读、可审、可回归的配置:

- **封装与隧道**:VLAN、QinQ、GRE 等任意深度层栈,next-proto 自动串接、可逐层覆盖。
- **Flow 会话维护**:从 YAML 配置展开为握手、seq/ack 推导、分段、挥手的完整包序列。
- **常见协议覆盖**:L2/L3/L4(ICMP/ICMPv6/TCP/UDP)到应用层(HTTP/DNS/FTP/...)。
- **异常协议畸形**:`payload_hex` 原始字节注入、错误 checksum/length、解析断链等。

## 有序层栈嵌套

pMaker 的 packet 是从外到内排列的 `stack`,同类型层可重复、可递归嵌套。

```yaml
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - tcp:  { sport: 40000, dport: 80, flags: [SYN], seq: 1000 }
```

```text
eth / ipv4 / tcp
eth / vlan / vlan / ipv4 / tcp      # QinQ
eth / ipv4 / gre / ipv4 / tcp       # GRE 隧道
eth / ipv4 / udp / dns
eth / ipv4 / icmp
```

next-proto / EtherType / checksum 伪首部默认自动推导;测试"解析断链""非标封装"时可逐层显式覆盖(如 `- vlan: { vid: 100, type: 0xffff }`)。

## Flow 状态维护

除了逐包写 stack,也可以描述一条有状态 TCP flow,展开器自动维护握手、seq/ack、MSS 分段、挥手:

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

```text
client                                              server
  │ ─────────────── SYN ──────────────────────────▶ │
  │ ◀──────────── SYN,ACK ───────────────────────── │
  │ ─────────────── ACK ──────────────────────────▶ │
  │ ───────── HTTP request ───────────────────────▶ │
  │ ◀──────── HTTP response ─────────────────────── │
  │ ───────────── FIN/ACK ... ────────────────────▶ │
```

## YAML 约定

- `stack` 从外到内排列,每个元素是单键 map;同类型层可重复(`vlan / vlan`)、可递归嵌套
- next-proto 默认自动推导,可逐层显式覆盖;原始字节用 `payload_hex`
- 时间可选:`base_time`(ISO8601 / UTC 绝对锚)+ 各级非负 `offset_time`,未指定则每包 1ms 按序排列
- 同一 scenario + seed 生成逐字节相同的 pcap

完整字段以 `internal/scenario` 类型定义与 `examples/` 为准。

## 测试

```bash
go test ./...
go test ./internal/scenario -run TestExamplesGolden -update   # 重生 golden pcap
```

## 安全边界

pMaker 是离线 pcap 构造工具:不主动发包、不打开 raw socket、不执行实时注入、不触碰网络接口。生成的 `.pcap` 可交给 `tcpreplay` 或分析工具回放。若未来增加实时注入能力,会放在独立且默认关闭的构建标签后并显式提示权限要求。

## CI/CD

通过 GitHub Actions 做质量门禁与发版([.github/workflows/](.github/workflows/)):

- **CI**:推 `main` / PR 时跑 gofmt、`go vet`、golangci-lint、`go test -race` 带覆盖率(上传 [Codecov](https://codecov.io))、`CGO_ENABLED=0` 构建冒烟。
- **Release**:推 `v*` tag 时用 [GoReleaser](https://goreleaser.com) 交叉编译多平台静态二进制并发布到 GitHub Releases。
- Lint 配置见 [.golangci.yml](.golangci.yml)(golangci-lint v2)。
