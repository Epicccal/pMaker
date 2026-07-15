# CLAUDE.md

本文件为 Claude Code 在本仓库工作时的指引。**开工前必读。**

## 项目概述

**pMaker** —— 一个用 Go 编写的 **Pcap 构造工具**,通过声明式配置批量生成各类协议的数据包,
产出 `.pcap` 文件(后续可扩展 `.pcapng`),用于对 **NDR / IDS 等流量监测设备**做检测能力测试。

- **形态**:CLI 工具优先(`pmaker gen -f scenario.yaml -o out.pcap`)。当前不对外暴露库 API,一切实现放在 `internal/`。
- **场景定义**:声明式 **YAML** 配置文件驱动。非开发者也应能编写/修改测试用例。
- **底层构包**:以 `gopacket` 序列化规范包为主,保留**原始字节兜底通道**用于构造畸形包/规避流量。

### 范围与安全边界(重要)

- 本工具**只离线生成 pcap 文件**,**默认不向网络发送任何数据包**。
- 用途是**授权环境下**对检测设备做能力验证(把生成的 pcap 用 tcpreplay 等回放)。
- 若将来新增实时注入(raw socket / pcap inject),必须放在**独立的、默认关闭的构建标签**后,并显式提示权限要求 —— 不要顺手把"离线构造器"变成"在线攻击流量发生器"。

## 技术栈与关键依赖

| 用途 | 选型 | 说明 |
|------|------|------|
| 语言 | **Go 1.25+** | `go.mod` 里 `go 1.25`(gopacket v1.7 要求);优先用现代标准库(`log/slog`、`errors.Join`、`slices`/`maps`) |
| 构包/分层 | **`github.com/gopacket/gopacket`** | 社区维护 fork(Google 原版已归档,**不要**用 `google/gopacket`) |
| 写 pcap | **`gopacket/pcapgo`** | **纯 Go,无需 libpcap,无 CGO**;跨平台静态编译 |
| 配置解析 | **`gopkg.in/yaml.v3`** | 只支持 YAML 格式配置文件 |
| CLI | **标准库 `flag`** + 子命令分发 | 子命令树变深再考虑引入 `cobra`,不要一上来就加依赖 |

**构建始终 `CGO_ENABLED=0`** —— 因为写 pcap 走纯 Go 的 pcapgo,无 libpcap 依赖,保证到处能静态编译。

## 目标目录结构

> 当前为新仓库,以下为**目标架构**;新增代码请遵循此布局。

```
cmd/pmaker/          # main 包:CLI 入口、flag 解析、子命令分发,尽量薄
internal/
  scenario/          # YAML schema 定义、解析、校验(带字段/行号级错误信息)
  builder/           # scenario 模型 -> gopacket layers -> 字节;序列化选项 & 原始字节兜底
  flow/              # 有状态流:TCP 握手、seq/ack 递推、时间戳编排
  proto/             # 各协议/封装层构造助手(eth/vlan/qinq/gre/mpls/vxlan/ip/tcp/udp/dns...),按需拆分
  writer/            # pcap 输出、LinkType、时间戳
examples/            # 可直接运行的示例场景 YAML,按协议分目录:examples/<协议>/<name>.yaml
```

golden pcap 测试基准不放在仓库根,而是**就近放在测试包内**:`internal/scenario/testdata/<协议>/<name>.pcap`
(Go 测试工作目录为包目录,测试以相对路径 `testdata/...` 读取)。**不要**在仓库根再建 `testdata/`。

**不要过早创建 `pkg/`。** 目前是 CLI 工具、无外部导入方;只有出现真实的外部消费者时,才把稳定接口提升到 `pkg/`(YAGNI)。

## 当前实现状态

最小出包链路已打通:`pmaker gen -f <yaml> -o <pcap>` 可真正出包。

- **已实现 stack 模型**:层 eth / vlan(Dot1Q)/ ipv4 / gre / tcp / udp / icmp / dns / payload / payload_hex / http_request / http_response;
  next-proto 自动串接、TCP/UDP checksum 伪首部、ICMP echo request/reply、DNS A/AAAA/CNAME/NS/PTR/MX/TXT/SOA/SRV、确定性时间戳、golden + gopacket 回读测试。
- **已实现 flow 基础版**:TCP 三次握手、seq/ack 自动推导、`segment.mss` 分段、SYN MSS option、
  HTTP 请求/响应、多轮消息、`close: fin` 四次挥手、`close: rst` 对端单包中断。
- **未实现 / 简化**:flow 的 overlap / 乱序 / 重传 / RTT 定时 / IP 分片 / 多流时间交织未做;
  畸形开关 `fix_lengths` / `checksum` **解析但忽略**(build 时 `slog.Warn`),真正的畸形 / 原始字节兜底待做;
  HTTP 头按 key 排序输出(未保留原序)。

## 核心数据流

```
scenario.yaml
   │  scenario 层:解析 + 校验(尽早失败,报错带字段路径)
   ▼
[]Packet 场景模型(每个 packet = 有序 layer 栈)
   │  builder 层:有序层栈(外→内)-> gopacket layers;自动串接 next-proto,可原始字节兜底
   │  flow 层:补全握手 / seq/ack / 时间戳
   ▼
gopacket.SerializeBuffer  ──(逐包)──▶  writer 层:pcapgo.Writer
   ▼
out.pcap
```

## 封装与隧道:任意层级栈(核心设计)

本工具必须支持**任意深度的封装嵌套**,而不是固定的 L2/L3/L4 三段式。典型场景:

- **VLAN(802.1Q)**:Ethernet → Dot1Q → IP
- **QinQ(802.1ad)**:Ethernet → Dot1Q(S-TAG)→ Dot1Q(C-TAG)→ IP —— **双层甚至多层 VLAN**
- **GRE 隧道**:IP → GRE →(内层完整报文:IP → TCP …)—— **隧道套报文,可递归**
- 未来同一套模型可扩展:MPLS、VXLAN、GTP-U、IP-in-IP、L2TP、Geneve …

因此有以下强约束:

1. **数据模型是"有序层栈",不是固定字段。** scenario 里每个 packet 是一个**从外到内的有序 layer 列表**,
   允许**同类型重复**(QinQ 两层 VLAN)和**递归嵌套**(GRE 内层再放一整个报文)。
   **禁止**把 `eth/ipv4/tcp` 写成固定槽位 —— 那样根本表达不了 QinQ/隧道。

2. **序列化顺序:最外层在前。** `gopacket.SerializeLayers(buf, opts, 最外层, …, 最内层, payload)`,
   由外到内依次传入,gopacket 内部逐层前置。builder 按层栈顺序喂进去即可。

3. **next-protocol / EtherType 串接是最易错的一环。** 每个封装层必须正确声明"下一层是什么",
   否则被测设备会在某一层解析断链:
   - `Ethernet.EthernetType`:后接 VLAN → `0x8100`;QinQ 外层 S-TAG → `0x88a8`(或按被测设备预期设 `0x8100`)
   - `Dot1Q.Type`:后接内层 VLAN → `0x8100`;后接 IPv4 → `0x0800`
   - `IPv4/IPv6.Protocol`:后接 GRE → `47`
   - `GRE.Protocol`:内层 IPv4 → `0x0800`;内层 Ethernet(TEB)→ `0x6558`

   builder 应能**按层栈自动推导**这些字段(默认行为),同时允许**逐层显式覆盖**
   —— 覆盖能力正是测试"设备对畸形/非标封装如何处理"的关键。

4. **QinQ 的 TPID 必须可配置。** 标准 S-TAG 是 `0x88a8`,但很多设备实现用 `0x8100` 做双层。
   测试点往往就是"设备认不认非标 TPID",所以 `tpid`/`ethertype` 要能逐层显式指定,**不能写死**。

5. **多层 IP 时,每个传输层的 checksum 绑定到"就近那层 IP"。** 内层 TCP 的
   `SetNetworkLayerForChecksum` 要指向**内层 IP**,不是外层。builder 按嵌套关系正确配对,
   否则内层 checksum 全错(除非该用例故意要错)。

6. **长度 / MTU / 分片:** 隧道叠加会增加头部开销。用于规避的分片可能发生在**外层或内层**,两处都要能构造。

## flow 场景设计(已实现基础版;后续扩展)

`flows` 不是一种新包结构,而是一个**有状态展开器**:维护 TCP 连接状态,把一段应用层脚本
展开成一串 **stack 模型的包**,再喂给现有 builder/writer。握手、四次挥手、多轮请求全部复用
同一套底座,展开器本身是唯一的新逻辑。

### TCP 状态不变式(务必遵守)

每方向各维护一个 `seq`,`ack` 由推导得到:

- `seq` 前进量 = `len(payload) + SYN(1) + FIN(1)`
- **纯 ACK 不消耗 seq**(带当前 seq,但不前进)
- 发包时 `ack` = **对端当前 seq**

握手(SYN → SYN,ACK → ACK)与四次挥手(FIN,ACK → ACK → FIN,ACK → ACK)据此推导。
`close` 可选 `fin`(四次)/ `rst`(单包)/ `none`;`open` 可选 `handshake` / `none`(已建连)。

### 多轮请求 = 更长的脚本(无需特殊逻辑)

状态在整个脚本里**持续存在**,第 N 轮的 seq/ack 从上一轮继续累加。HTTP keep-alive / 流水线
不是特例,只是 `messages` 列表更长。展开器负责在前插握手、后插挥手、按 `ack_policy` 插对端 ACK。

### schema(canonical)

```yaml
flows:
  - name: http-keepalive
    stack:                         # flow 中 src = TCP SYN 发起方,dst = SYN 接收方
      - eth:  { src: "...", dst: "..." }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000, mss: 1460 }
      - tcp_session: { open: handshake, close: fin } # open: handshake|none; close: fin|rst|none
    messages:                      # 有序、方向性的应用层消息
      - from: src
        stack:
          - http_request: { method: GET, url: /a }
      - from: dst
        stack:
          - http_response: { status: 200, body: "..." }
      - from: src                 # 第 2 轮
        stack:
          - http_request: { method: GET, url: /b }
      - from: dst
        stack:
          - http_response: { status: 200, body: "..." }
```

`from` 指方向(`src`/`dst`),消息体也是一个有序 `stack`;当前 flow message 仅支持一个 **payload 生产层**
(`http_request` / `http_response` / `payload_hex` / `payload`)。反向消息会自动反转 eth/ipv4/tcp 的 src/dst/sport/dport.

### 分段与规避(NDR/IDS 测试重点)

每条消息可挂 `segment:` 策略,把一条应用消息切成多个 TCP 段(seq 按字节偏移铺开):

```yaml
segment: { mss: 8, order: shuffled, overlap: 4, retransmit: [1] }
#           小段    乱序(seed 派生)  重叠段     重传第 1 段
```

乱序 / 重叠 / 重传只是"发包顺序与 seq 的组合",状态机本身不变。检测设备的**重组能力**是主战场。

### 后续扩展

当前 flow 已支持基础 TCP 会话展开。后续若要支持多流按显式时间戳交织、
更通用的封装 stack 反转或外层/内层分片,可引入类似 `PlannedPacket{ Stack []Layer; Time time.Time }` 的中间态,
让 packets 与 flows 汇流后统一排序再写盘。

当前 `flow.Expand` 返回 `[]scenario.Packet`,builder 继续消费 stack 模型并复用 per-stack 序列化、checksum 伪首部和 next-proto 串接逻辑。

### 约束

- **确定性**:时间戳由 `base + 累计 rtt` 派生,seed 控制乱序/抖动,不用 `time.Now()`(保持 golden 可比对)。
- **封装组合**:当前 flow.stack 先支持 eth/ipv4/tcp/tcp_session;若要把整条会话套进 QinQ/GRE,后续再升级为更通用的 stack 反转。
- **UDP**:退化情形——无握手/挥手、无 seq/ack 的一串数据报(DNS、QUIC 探测)走同一抽象。
- **测试**:每个 flow 出 golden pcap;回读用 gopacket `reassembly` 重组 TCP 流,断言应用层字节与脚本一致、无空洞、握手/挥手标志序列正确。

## 领域关键约束(最容易踩坑,务必遵守)

1. **畸形包必须能绕过自动修正。** 这是 IDS 测试工具的立身之本。
   - 规范包:`SerializeOptions{FixLengths: true, ComputeChecksums: true}`。
   - 畸形/规避包:允许**逐字段关闭** `FixLengths` / `ComputeChecksums`,并允许写入非法的 length、错误 checksum、重叠分片等。
   - 提供**原始字节注入**(如配置里的 `payload_hex`: `0x...`):当 gopacket 无法表达某种畸形时,直接落原始字节。**绝不能**因为"修正了 checksum/length"而让本应畸形的测试包变成合规包 —— 那等于悄悄废掉了这条用例。

2. **TCP/UDP checksum 依赖 IP 伪首部。** 序列化前必须
   `transportLayer.SetNetworkLayerForChecksum(ipLayer)`,否则 checksum 恒错。除非该用例**故意**要错误 checksum。

3. **输出必须确定性可复现。** 同一份 scenario + 同一 seed → **逐字节相同**的 pcap。
   - 不要用 `time.Now()`:时间戳从配置读取,或从 seed 派生。
   - 所有"随机"(随机端口、IP ID、payload 填充)都走**可配置 seed** 的 `math/rand`,禁用全局 `rand`。
   - 保证 map 遍历等顺序稳定。
   - 这是 golden-file 测试和"测试用例可归档复现"的前提。

4. **LinkType 要选对。** 含以太头 → `layers.LinkTypeEthernet`;仅 L3 → `LinkTypeRaw`/`LinkTypeIPv4`。写反了监测设备解析会全错。

5. **网络字节序为大端。** gopacket 自动处理;走原始字节通道时自己保证大端。

## 常用命令

```bash
# 构建(静态、无 CGO)
CGO_ENABLED=0 go build -o bin/pmaker ./cmd/pmaker

# 运行:从场景生成 pcap
./bin/pmaker gen -f examples/http/get.yaml -o out.pcap

# 校验场景文件(不出包,只查 schema)
./bin/pmaker validate -f examples/http/get.yaml

# 测试 / 覆盖率
go test ./...
go test -race ./...
go test -cover ./...

# 重新生成 golden 基准(约定用 -update)
go test ./internal/scenario -run TestExamplesGolden -update

# 质量门禁(提交前必跑)
gofmt -l .        # 应无输出
go vet ./...
golangci-lint run # 若已安装
```

## 编码规范

- **格式化**:`gofmt` / `goimports`;命名遵循 Go 惯例(导出加注释、缩写全大写如 `TCP`/`IP`/`ID`)。
- **错误处理**:一律 `fmt.Errorf("...: %w", err)` 包装并上抛;库代码路径**不 panic**。CLI 在 `cmd/` 层统一打到 stderr 并以非零码退出。
- **配置校验尽早、报错够具体**:指出是哪个包、哪个字段、期望什么。用户大多不是开发者,错误信息就是他们的调试器。
- **日志**:用 `log/slog`;正常输出走 stdout,诊断/进度走 stderr。
- **测试**:表驱动;新协议/新字段都要有对应的 golden pcap;关键路径跑 `-race`。
- **依赖克制**:标准库能做的不引第三方;新增依赖前先问"是否真需要"(参见构包/CLI 选型说明)。

## 配置文件约定

- 只支持 YAML 格式配置文件。
- 顶层是**有序的 packet 列表**或 **flow 场景**;字段名 `snake_case`。
- **每个 packet 是一个 `stack`:从外到内的有序 layer 列表**,每个元素是单键 map(`- vlan: {…}`),
  **允许同类型重复**(QinQ 两层 VLAN)和递归嵌套(GRE 内层再放报文)。
- 封装层的 next-protocol / ethertype **默认自动推导**,可逐层用 `type` / `tpid` / `ethertype` 显式覆盖(制造断链等畸形)。
- 缺省字段走合理默认(自动 seq、自动 checksum、自动串接)。
- 畸形用例通过**显式开关**表达意图:`fix_lengths: false` / `checksum: 0xdead` / 覆盖 `type` 断链 / `payload_hex: "0x…"`.

示意(最终 schema 以 `internal/scenario` 的类型定义为准):

```yaml
# examples/tunnel/qinq_gre.yaml
link_type: ethernet
seed: 42
packets:
  # ① QinQ:双层 VLAN 承载普通 TCP
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb", ethertype: 0x88a8 }  # S-TAG TPID
      - vlan: { vid: 100, tpid: 0x8100 }   # 外层 S-TAG,下一层仍是 VLAN
      - vlan: { vid: 200 }                 # 内层 C-TAG,next 自动推导为 IPv4
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - tcp:  { sport: 40000, dport: 80, flags: [SYN], seq: 1000 }

  # ② GRE 隧道:外层 IP → GRE → 内层完整报文
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "1.1.1.1", dst: "2.2.2.2" }          # 外层,protocol 自动 = GRE(47)
      - gre:  {}                                           # protocol 自动 = 内层 ethertype
      - ipv4: { src: "192.168.1.1", dst: "192.168.1.2" }   # 内层 IP
      - tcp:  { sport: 1234, dport: 443, flags: [SYN] }

  # ③ 畸形用例:故意断链 + 错误 checksum + 原始字节
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb", ethertype: 0x8100 }
      - vlan: { vid: 100, type: 0xffff }   # 显式覆盖 next-proto,制造解析断链
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", checksum: 0xdead, fix_lengths: false }
      - payload_hex: 0xdeadbeef                # gopacket 无法表达时直接落原始字节
```

## 测试策略

1. **Golden pcap 比对**:`internal/scenario/testdata/<协议>/<name>.pcap` 逐字节比对(依赖确定性输出);用 `-update` 重生。
2. **回读校验**:生成的 pcap 能被 gopacket 正确解析(规范包场景)。
3. **可选集成**:若环境有 `tshark`,可用 `tshark -r out.pcap` 交叉验证协议解析(集成测试,非必需依赖)。

## 新增一个协议的步骤(清单)

1. `internal/proto/` 加该协议的构造助手(优先复用 gopacket 现成 layer)。
2. `internal/scenario/` 加该协议的 schema 结构体 + 校验规则。
3. `internal/builder/` 接线:scenario 字段 → layer;暴露畸形开关(关闭 fix/checksum、raw 注入)。
   **若是封装层**,还须实现 next-proto/ethertype 的自动推导,并允许逐层显式覆盖。
4. `examples/<协议>/` 加一个规范用例 + 一个畸形用例(单职责、小而聚焦);**封装/隧道层再加一个嵌套用例(如 QinQ / GRE 套接)**。
5. 加 golden 测试并生成基准;`go test -race ./...` 通过。
6. README/示例文档同步。
