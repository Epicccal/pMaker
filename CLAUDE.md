# CLAUDE.md

本文件为 Claude Code 在本仓库工作时的指引。**开工前必读。**

## 1. 项目概述

**pMaker** —— Go 编写的 pcap 构造工具,用声明式 YAML 批量生成各协议数据包,产出 `.pcap` 文件。

形态是 CLI 优先(`pmaker gen -f scenario.yaml -o out.pcap`)。不对外暴露库 API,实现全在 `internal/`。
另有 MCP server(`cmd/pmaker-mcp`),把生成能力与语法文档暴露给其他大模型。

**安全边界**:本工具只离线生成 pcap 文件,不向网络发送任何数据包。用途是在授权环境下做流量验证,
把生成的 pcap 用 tcpreplay 等回放。新增实时注入须放在独立且默认关闭的构建标签后,并显式提示权限要求。

## 2. 技术栈与关键依赖

| 用途 | 选型 | 约束 |
|------|------|------|
| 语言 | Go 1.25+ | `go.mod` 声明 `go 1.25.5`;优先用现代标准库(`log/slog`、`slices`) |
| 构包分层 | `github.com/gopacket/gopacket` | 社区维护 fork;不要用已归档的 `google/gopacket` |
| 写 pcap | `gopacket/pcapgo` | 纯 Go,无 libpcap 依赖,无 CGO |
| 配置解析 | `gopkg.in/yaml.v3` | 只支持 YAML |
| 压缩 | `klauspost/compress`、`andybalholm/brotli` | HTTP 内容与传输编码,输出确定性 |
| CLI | 标准库 `flag` + 子命令分发 | 子命令树变深再考虑 `cobra` |
| MCP | `mark3labs/mcp-go` | stdio transport |

构建始终 `CGO_ENABLED=0`。写 pcap 走纯 Go 的 pcapgo,保证跨平台静态编译。

## 3. 目录结构

```
cmd/pmaker/            # CLI 入口:flag 解析、子命令分发,尽量薄
cmd/pmaker-mcp/        # MCP server:generate_yaml / generate_pcap 工具 + resources
  resources/schema/    # 每协议一份字段速查 markdown,整体 embed
internal/
  scenario/            # schema 定义、解析、校验;AbsTime / Offset / PlannedPacket 类型
  builder/             # scenario 模型 -> gopacket layers -> 字节
  flow/                # 有状态流:TCP 握手、seq/ack 递推,只产 stack 包不含时间
  plan/                # 时间编排:packets 与 flows 汇流成 PlannedPacket,按 Time 排序
  writer/              # pcap 输出、LinkType 选择
  summary/             # 包摘要展示模型与终端排版
  util/                # 协议无关原语:chunked / compress / crlf / cte / dotframe
  golden/              # 端到端 golden pcap 测试包
    testdata/<协议>/   # golden 基准 pcap
examples/<协议>/       # 可直接运行的示例场景 YAML
```

golden 基准就近放测试包内,不在仓库根另建 `testdata/`。Go 测试工作目录为包目录,用相对路径读取。

不要过早创建 `pkg/`。目前无外部导入方,只有出现真实外部消费者时才把稳定接口提升上去(YAGNI)。

## 4. 核心数据流

```
scenario.yaml
   │  scenario:解析 + 校验(尽早失败,报错带字段路径)
   ▼
Scenario(Packets + Flows,每个 packet = 有序 layer 栈)
   │  flow:把 flows 展开成 stack 包,补全握手与 seq/ack
   │  plan:packets 与 flows 汇流成 []PlannedPacket{Stack, Time},按 Time 稳定排序
   ▼
[]PlannedPacket(已带显式时间戳、已排序)
   │  builder:有序层栈(外到内)-> gopacket layers,自动串接 next-proto
   ▼
gopacket.SerializeBuffer ──(逐包)──▶ writer:pcapgo.Writer ──▶ out.pcap
```

## 5. 已实现层与特性

层名是 `internal/scenario/layer_decode.go` 的 `layerDecoders` 单一真相源,加层只在那里登记。

| 分层 | 层名 |
|------|------|
| L2 | `eth`、`vlan`(Dot1Q,支持 QinQ 多层) |
| L3 | `ipv4`、`ipv6`、`gre`、`vxlan` |
| L4 | `tcp`、`udp`、`tcp_session`(flow 会话开关,非 wire 层)、`udp_session`(flow UDP 会话标记,非 wire 层,必写) |
| 控制 | `icmp`、`icmpv6` |
| 应用 | `dns`、`http_request`、`http_response`、`ftp_request`、`ftp_response`、`telnet` |
| 应用 | `smtp_request`、`smtp_response`、`pop3_request`、`pop3_response` |
| 应用 | `imap_request`、`imap_response`、`eml_data` |
| 应用 | `tftp`(单层五 opcode 分派)、`tftp_transfer`(message 级宏,仅 UDP flow,展开成 DATA/ACK 锁步,非 wire 层) |
| 兜底 | `payload`、`payload_hex` |

子结构不是层,不能写进 `stack`:`multipart`(嵌在 `http_request` / `http_response` / `eml_data`)、
`literal`(嵌在 `imap_request` / `imap_response`)。

已实现特性:

- next-proto 与 EtherType 按层栈自动推导,可逐层显式覆盖
- IP MTU 自动分片:`ipv4` / `ipv6` 层写 `mtu` 即按 8 字节对齐块逐片切出,
  IPv6 自动插 Fragment 扩展头(next_header=44);分片 ID 由确定性计数器分配
  (只在真正分片时消耗),各片与原包同刻;`mtu` 与 length/checksum 覆盖字段同层互斥
- TCP/UDP checksum 伪首部绑定就近 IP 层,多层 IP 时绑内层
- `checksum` 与 `length` 两态覆盖:不写=自动算,写=原样落值
- 确定性时间戳,全程不用 `time.Now()`
- 隧道递归嵌套:GRE 套报文、VXLAN 承载二层
- 方向化 VLAN VID(`vlan.src_vid` / `dst_vid`,仅 flow.stack 有效)
- ICMP echo 与错误报文(`quote` / `quote_from`;quote_from 复用被引包 wire 首片的
  ip-down 字节,前向引用硬错、引用环校验期拦截)
- DNS A/AAAA/CNAME/NS/PTR/MX/TXT/SOA/SRV
- 邮件与文本协议的命令、响应、多行续行
- RFC 5322 正文层 `eml_data`,成帧由接入层强制
- RFC 2046 multipart body,含 base64 与 quoted-printable
- TFTP 全量报文(RFC 1350/2347 五 opcode + OACK + 数字透传);`tftp_transfer` 宏在
  flow 展开期自动降解成 DATA/ACK 锁步序列(块数超上限硬错)
- HTTP 内容编码 `content_encoding` ∈ gzip / deflate / deflate_raw / br / zstd / compress
- HTTP 传输编码 `transfer_encoding` ∈ chunked / gzip / deflate / deflate_raw / compress
  (`br` 与 `zstd` 只是内容编码,`chunked` 只是传输编码,放错一侧硬错)
- 自动 `Content-Length`(`auto_content_length: true`)
- 文件占位符 `@file(path)` 注入原始字节
- 一致性软告警:FTP 端口协商、multipart、HTTP 成帧、IMAP literal、flow 覆盖值逐包同值、
  TFTP(RQ 端口 / mode / DATA 超长 / 无关字段)
- MCP server:两个工具 + schema/examples resources
- golden pcap 逐字节比对 + gopacket 回读

未实现:随机化与 `seed`(无任何随机源);flow 的乱序 / 重叠 / 重传。
IP 分片已实现为 `mtu` 自动分片(只此一条通道,畸形分片如 DF 置位、重叠片不在
范围内,须整段 `payload_hex`);分片包的 gopacket 回读只到 Fragment 层,L4 须
重组后解码。

`gre` / `vlan` / `icmp` / `icmpv6` 不开放长度字段:协议头本身没有载荷长度字段。
`eth` 暂不开放 802.3 长度:gopacket 会把显式值 > 0x0600 判为错误,且无条件补齐到 60 字节,造不出 runt 帧。
这类畸形需在 stack 中省去 `eth`,整帧用 `payload_hex` 落原始字节。

## 6. 设计约束

1. **畸形包必须能绕过自动修正。** 规范包用 `SerializeOptions{FixLengths: true, ComputeChecksums: true}`;
   畸形包允许逐字段关闭修正、写入非法 length 与错误 checksum。gopacket 表达不了时用 `payload_hex` 落原始字节。
   绝不能因为"修正了 checksum/length"把畸形用例变成合规包 —— 那等于悄悄废掉这条用例。
2. **数据模型是有序层栈,不是固定字段。** 每个 packet 是从外到内的有序 layer 列表,
   允许同类型重复(QinQ 双层 VLAN)与递归嵌套(GRE 内层再放整个报文)。禁止写成 `eth/ipv4/tcp` 固定槽位。
3. **序列化顺序最外层在前。** builder 按层栈顺序把层喂给 `gopacket.SerializeLayers`,gopacket 内部逐层前置。
4. **next-proto 串接是最易错的一环。** 每个封装层须正确声明下一层,否则解析端断链。
   默认按层栈自动推导,同时允许用 `type` / `ethertype` 逐层覆盖 —— 覆盖能力正是构造断链畸形的手段。
   QinQ 的 TPID 不能写死:标准 S-TAG 是 `0x88a8`,但很多设备用 `0x8100` 做双层,认不认非标 TPID 就是验证点。
5. **多层 IP 时 checksum 绑定就近那层 IP。** 序列化前调 `SetNetworkLayerForChecksum`,内层 TCP 指向内层 IP。
   配错则内层 checksum 全错,除非用例故意要错。
6. **输出必须确定性可复现。** 同一份 scenario 产出逐字节相同的 pcap:时间戳从配置读取、map 遍历顺序稳定。
   这是 golden 测试与用例归档复现的前提。将来引入随机化须走可配置 seed,禁用全局 `rand`。
7. **LinkType 要选对。** 场景里 `link_type` 取 `ethernet` / `raw` / `ipv4` / `ipv6`,分别映射到
   `layers.LinkTypeEthernet` / `LinkTypeRaw` / `LinkTypeIPv4` / `LinkTypeIPv6`。含以太头选 `ethernet`,
   仅 L3 选 `raw` 或对应地址族。写反了解析端会全错。
8. **网络字节序为大端。** gopacket 自动处理;走原始字节通道时自己保证。
9. **配置约定。** 只支持 YAML,字段名 `snake_case`,层写成单键 map(`- vlan: {…}`)。
   顶层是 `packets` 有序列表或 `flows` 场景;缺省字段走合理默认(自动 seq、自动 checksum、自动串接)。
10. **`@file(<path>)` 占位符。** 任意 string 字段可写 `@file(path)`,解析时替换为文件原始字节(支持二进制)。
    可只占字段值一部分,可多个拼接;`@@` 转义为字面 `@`,裸 `@` 原样保留。
    路径须落在 `baseDir` 内(CLI = scenario 所在目录,MCP = `workdir`),越界一律硬错 ——
    `baseDir` 是唯一信任边界,MCP 下场景由远端模型生成,任意路径读取会成为可被提示注入利用的读原语。
    `payload_hex` 是 hex 编码字段,注入原始字节会破坏语义,二进制内容用 `payload`。
    被引文件需随场景归档,否则换机器不可复现。

### 场景示例(packets)

```yaml
link_type: ethernet
packets:
  - stack:                                     # QinQ:双层 VLAN 承载 TCP
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb", ethertype: 0x88a8 }
      - vlan: { vid: 100, type: 0x8100 }       # 外层 S-TAG,下一层仍是 VLAN
      - vlan: { vid: 200 }                     # 内层 C-TAG,next 自动推导为 IPv4
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - tcp:  { sport: 40000, dport: 80, flags: [SYN], seq: 1000 }
  - stack:                                     # GRE 隧道:外层 IP 套整个内层报文
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "1.1.1.1", dst: "2.2.2.2" }            # protocol 自动 = GRE(47)
      - gre:  {}
      - ipv4: { src: "192.168.1.1", dst: "192.168.1.2" }
      - tcp:  { sport: 1234, dport: 443, flags: [SYN] }
  - stack:                                     # 畸形:断链 + 错 checksum + 原始字节
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb", ethertype: 0x8100 }
      - vlan: { vid: 100, type: 0xffff }       # 覆盖 next-proto,制造解析断链
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", checksum: 0xdead, total_length: 9999 }
      - payload_hex: "0xdeadbeef"
```

## 7. Flow 场景

`flows` 不是新包结构,而是一个有状态展开器:把一段方向性消息脚本展开成一串 stack 包,
再喂给现有 builder 与 writer。会话分两种形态,由会话层决定:

- **TCP 会话**(`tcp_session`,可省略):维护 TCP 连接状态,握手、挥手、对端 ACK、
  seq/ack 递推全部自动;多轮请求复用同一套底座。
- **UDP 会话**(`udp_session`,零字段标记层,**必写**):无握手/挥手/ACK,每条 message
  恰好展开一个 UDP 数据报,`from: dst` 交换端点后从对端发出。`message.stack` 不按协议
  收窄(数据报协议随 TFTP/QUIC 等持续进来),TCP 流式层进数据报产软告警
  `udp.stream-app-layer`(按流式层正向清单判定,清单外默认不告警);`segment` 切段
  不支持(UDP 无流重组,切出的数据报单独无法解析);端口切换(TFTP TID 式)走两条
  flow + `start_after`。详见 `cmd/pmaker-mcp/resources/schema/udp_session.md` 与
  `_why_udp_session.md`。

### Schema(canonical)

```yaml
flows:
  - name: http-keepalive
    stack:                         # flow 中 src = SYN 发起方,dst = SYN 接收方
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000, mss: 1460 }
      - tcp_session: { open: handshake, close: fin }   # open: handshake|none;close: fin|rst|none
    messages:                      # 有序、方向性的应用层消息
      - from: src
        stack:
          - http_request: { method: GET, url: /a }
      - from: dst
        segment: { mss: 8, interval: "+10ms" }         # 切段大小 + 段间间隔
        stack:
          - http_response: { status: 200, body: "hello world" }
```

`from` 取 `src` 或 `dst`,消息体也是有序 `stack`。`message.stack` 只允许 payload 生产层
(`http_request` / `payload_hex` / `payload` 等;UDP 会话不收窄,TCP 流式层产
`udp.stream-app-layer` 软告警,按流式层正向清单判定),
须至少一个,按声明顺序拼接;eth/ipv4/tcp 由 `flow.stack` 提供,不在 message 里重复。
反向消息自动反转 eth/ipv4/tcp 端点。
VXLAN 单层整栈模板同时反转内外层端点,VNI 与 outer UDP 端口保持声明值。

### TCP 状态不变式

每方向各维护一个 `seq`,`ack` 由推导得到:

1. `seq` 前进量 = `len(payload) + SYN(1) + FIN(1)`。
2. 纯 ACK 不消耗 `seq`:带当前 `seq`,但不前进。
3. 发包时 `ack` = 对端当前 `seq`。

握手(SYN → SYN,ACK → ACK)与挥手(FIN,ACK → ACK → FIN,ACK → ACK)据此推导。
状态在整个脚本里持续存在,第 N 轮的 seq/ack 从上一轮继续累加 —— keep-alive 与流水线只是 `messages` 更长。
每条消息在最后一段后 `+1ms` 插一个对端 ACK。

### 时间编排

`internal/plan.Plan` 是 packets 与 flows 的汇流点:产出 `PlannedPacket{Stack, Time}` 列表,
按 `Time` 稳定排序后交 `builder.BuildPlanned`。时间语义是"相对上一项 + 跨流独立",各字段参照点如下:

| 字段 | 类型 | 参照点 |
|------|------|--------|
| `base_time` | `AbsTime` | 场景唯一绝对锚,仅 ISO8601 UTC;缺省 = 确定性 2020 基准 |
| `packet.offset_time` | `Offset` | 上一包(第一包相对 `base_time`);缺省接续默认游标 +1ms |
| `flow.offset_time` | `Offset` | 流锚基准 = `base_time`,或 `start_after` 被引时刻;缺省 0 |
| `message.offset_time` | `Offset` | 上一条消息末尾(TCP 第一条相对握手完成,UDP 第一条相对流锚);缺省紧接 |
| `segment.interval` | `Offset` | 同一消息各数据段之间;缺省 `flow.DefaultStep` = 1ms |

所有 `Offset` 只接受非负时长(如 `+1.5s` / `500ms` / `0s`)。负值在解析阶段即失败 ——
负偏移通常意味着 `base_time` 选错了起点,应把 `base_time` 提前。写 `+1s` 给 `base_time` 同样失败。

无 `offset_time` 的多条 flow 在 `base_time` 并发(模拟浏览器多连接并行),想顺序就显式给递增 offset。
对端 ACK 是伴生控制包,用 `DefaultStep`,不被数据段节奏传染。同 `Time` 的包保持声明顺序(稳定排序)。

### 跨流 start_after

`flow.start_after` 与 `message.start_after` 写 `"flow名"`(该 flow 挥手后)或 `"flow名.message_id"`
(该消息整组完成)。置则起点 = 被引时刻 + 自身 `offset_time`,取代默认参照点。这是显式 opt-in 依赖,
默认的跨流独立性不变。被引 flow 须具名且唯一,被引 message 须在流内有唯一 `message_id`,可声明在后。
`message.start_after` 禁止同流自引:流内顺序由 message 链式游标保证。

`plan.Plan` 两段式处理:阶段一 `scheduler` 按事件粒度递归 + 记忆化,只算时刻不发包;
阶段二各 flow 拿 per-message 起始时刻表独立 `flow.Expand`,seq/ack 在单次展开内连续维护。
循环依赖由 `validateStartAfter` 的事件粒度三色 DFS 在校验阶段拦截。事件粒度而非 flow 粒度是关键:
FTP 式 `control.150 → data → control.226` 的合法交错在事件粒度无环,flow 粒度会误判为互等死锁。

FTP 控制通道与数据通道就用两条独立 flow 加 `start_after` 表达消息级双向交错,不引入关联字段。

## 8. 常用命令

```bash
# 构建(静态、无 CGO)
CGO_ENABLED=0 go build -o bin/pmaker ./cmd/pmaker
CGO_ENABLED=0 go build -o bin/pmaker-mcp ./cmd/pmaker-mcp

# 从场景生成 pcap
./bin/pmaker gen -f examples/http/get.yaml -o out.pcap

# 只校验场景文件,不出包
./bin/pmaker validate -f examples/http/get.yaml

# 启动 MCP server(供其他大模型调用)
./bin/pmaker-mcp -workdir .

# 测试与覆盖率
go test ./...
go test -race ./...

# 重新生成 golden 基准
go test ./internal/golden -run TestExamplesGolden -update

# 质量门禁:提交前必跑,一条命令(不要手写命令序列,会与 Makefile 漂移)
make quality
```

未装 `golangci-lint` 时 `make quality` 会软跳过 lint 并只给警告,而 CI 无条件强制。
看到"已跳过"就别当本地绿,装上再跑一遍。需要逐字复现 CI 时用 `make ci`。

## 9. 编码规范

- **格式化**:`gofmt` / `goimports`;命名遵循 Go 惯例,缩写全大写如 `TCP` / `IP` / `ID`,导出加注释。
- **错误处理**:一律 `fmt.Errorf("...: %w", err)` 包装上抛;库代码路径不 panic。
  CLI 在 `cmd/` 层统一打到 stderr 并以非零码退出。
- **校验尽早、报错够具体**:指出哪个包、哪个字段、期望什么。用户大多不是开发者,错误信息就是他们的调试器。
- **日志**:用 `log/slog`,仅限 `cmd/` 入口层;正常输出走 stdout,诊断与进度走 stderr。
- **依赖克制**:标准库能做的不引第三方;新增依赖前先问是否真需要。
- **测试**:表驱动;新协议与新字段都要有对应的 golden pcap;关键路径跑 `-race`。
  生成的 pcap 还须能被 gopacket 正确回读(规范包场景)。

**异常模型只有两套**(见 `internal/scenario/diagnostic.go`):

1. **硬错 = `error`**,由 `Validate` 返回并带字段路径,失败即中止,不迁移进告警模型。
2. **软告警 = `Diagnostic{Code, Path, Message}`**,经 `scenario.Warnings` 聚合,
   CLI 渲染为 stderr 文本、MCP 渲染为结构化 `warnings`。`Code` 是稳定对外契约
   (`"<协议>.<问题>"` kebab-case,常量表是单一真相源,只能新增不能改名),`Path` 是声明级字段路径。
3. **`internal/` 内禁止用 slog 打用户可见诊断。** 日志不回流调用方,MCP 走 stdio,模型永远看不到。
   由 `diagnostic_test.go` 的守卫测试锁定。

**测试文件命名规约**:

1. 一一对应:`xxx.go` ↔ `xxx_test.go`,不写看不出归属的名字。单个源文件的测试过大时按
   `<源文件名>_<主题>_test.go` 拆分,前缀与源文件保持一致。
2. 跨文件复用的辅助集中放 `helpers_test.go`,不要每个测试文件复制一份。
   需被非 `_test` 文件引用时命名为 `testing.go`。
3. 端到端测试统一落在 `internal/golden`:比对 `testdata/*.pcap`,或跨三个以上包断言最终 pcap 字节。
   拿 examples 当输入、只断言本包行为的单测留在各包自己的 `_test.go`,文件顶部注释写明覆盖范围。

## 10. 新增一个协议的步骤

1. `internal/builder/` 加构造助手,优先复用 gopacket 现成 layer;新协议单独成文件 `<proto>.go`。
2. `internal/scenario/` 加 schema 结构体与校验规则,并在 `layerDecoders` 登记层名。
   若是 TCP 流式应用层(语义为「字节流的一段」),还须登记进 `flow_stack.go` 的
   `tcpStreamLayers`(UDP 会话的流式层告警清单,漏登记会漏告警)。
3. builder 接线:scenario 字段到 layer,暴露畸形开关(关闭 fix/checksum、原始字节注入)。
   封装层还须实现 next-proto 与 ethertype 自动推导,并允许逐层覆盖。
4. `examples/<协议>/` 加一个规范用例与一个畸形用例,单职责、小而聚焦;封装层再加一个嵌套用例。
5. 同步 MCP schema resource:`cmd/pmaker-mcp/resources/schema/<proto>.md`。schema 目录整体 embed,
   加文件即生效。`examples/` 随 `examples.go` 的 `all:*` embed 自动收录,但新示例须重新编译才生效。
6. 加 golden 测试并生成基准;`go test -race ./...` 通过。
7. README 与示例文档同步。

MCP 客户端靠 schema resource 带内学语法,脱节会让模型写出无效 YAML。这条约束由测试保证,不靠人记:
`cmd/pmaker-mcp/resources_schema_test.go` 的三条测试锁住层名与文档双向对应、文档 YAML 片段真能过校验、
报错文案与校验器实际输出一致。改了字段语义或校验措辞后跑 `go test ./cmd/pmaker-mcp/`,红了就是文档没跟上。
子结构非层,需在 `overview.md` 的子结构小节登记并单独建档,嵌入它的层要加字段说明并链过去。
设计立场文档写成 `_why_<topic>.md`,由层文档的"相关"节引路,`_` 前缀不参与层覆盖性比对。
