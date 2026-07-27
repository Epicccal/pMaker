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
  scenario/          # YAML schema 定义、解析、校验(带字段/行号级错误信息);AbsTime / Offset / PlannedPacket 类型
  builder/           # scenario 模型 -> gopacket layers -> 字节;BuildPlanned 消费已排序的 PlannedPacket
  flow/              # 有状态流:TCP 握手、seq/ack 递推(只产 stack 包,不含时间)
  plan/              # 时间编排:packets + flows 汇流成 PlannedPacket,按 Time 排序
  writer/            # pcap 输出、LinkType(时间戳取自 builder.OutPacket.Time)
examples/            # 可直接运行的示例场景 YAML,按协议分目录:examples/<协议>/<name>.yaml
```

golden pcap 测试基准不放在仓库根,而是**就近放在测试包内**:`internal/scenario/testdata/<协议>/<name>.pcap`
(Go 测试工作目录为包目录,测试以相对路径 `testdata/...` 读取)。**不要**在仓库根再建 `testdata/`。

**不要过早创建 `pkg/`。** 目前是 CLI 工具、无外部导入方;只有出现真实的外部消费者时,才把稳定接口提升到 `pkg/`(YAGNI)。

## 当前实现状态

最小出包链路已打通:`pmaker gen -f <yaml> -o <pcap>` 可真正出包。

- **已实现 stack 模型**:层 eth / vlan(Dot1Q)/ ipv4 / gre / tcp / udp / icmp / dns / payload / payload_hex / http_request / http_response / ftp_request / ftp_response;
  next-proto 自动串接、TCP/UDP checksum 伪首部、ICMP echo request/reply、DNS A/AAAA/CNAME/NS/PTR/MX/TXT/SOA/SRV、FTP 控制连接命令/响应(RFC 959 多行续行)、确定性时间戳、golden + gopacket 回读测试。FTP 控制通道 ↔ 数据通道用**两条独立 flow + `start_after`** 表达(message 级双向交错:数据 `start_after control.<150>`、226 `start_after data`),不引入 `data_connection` 等关联字段。**FTP 命令/响应码校验对齐 DNS 模式**:`ftp_request.command` 校验已知命令表(RFC 959 核心 + 常见扩展,大小写不敏感),`ftp_response.code` 校验三位 100-599(首位 1-5);未列入的命令、越界响应码报错,引导改用 `payload` / `payload_hex` 原始字节通道构造非标 / 畸形值(与全项目「非标值走原始字节兜底」约定一致)。
- **已实现 flow 基础版**:TCP 三次握手、seq/ack 自动推导、`segment.mss` 分段、SYN MSS option、
  HTTP 请求/响应、多轮消息、`close: fin` 四次挥手、`close: rst` 对端单包中断。
- **已实现 flow 逐消息定时**:`message.offset_time`(相对上一条消息末尾的偏移,锚定单条消息整组)、
  `segment.interval`(同消息各数据段间隔,模拟慢速分段/RTT);`flow.Expand` 自管时间轴,
  plan 退回汇流 + 稳定排序。**时间语义为「相对上一包 + 跨流独立」**:流内链式——每条消息
  = 上一条末尾 + offset(`start=msgCursor+offset`,第一条相对握手完成后);offset>=0 天然单调、
  无需夹紧,慢响应拖慢下一条请求(正常非流水线 HTTP);挥手接在最后一条消息之后(传完才关)。
- **已实现 PlannedPacket 时间编排**:`internal/plan.Plan` 把 standalone packets 与 flows 展开包汇流成
  `PlannedPacket{ Stack; Time }` 列表,按显式时间戳稳定排序后再交 `builder.BuildPlanned` 序列化。
  时间锚为 `base_time`(AbsTime,唯一绝对锚,仅 ISO8601);`Offset` 类型在解析阶段结构性保证取值合法
  (非负时长),不依赖运行期校验。**各 offset_time 的参照点因字段而异**:`packet.offset_time` 相对
  **上一包**(第一包相对 base);`flow.offset_time` 相对 **base_time**(跨流独立、可并行,flow 不消费/推进
  packet 游标);`message.offset_time` 相对 **上一条消息**(第一条相对握手完成后)。
- **已实现消息粒度两段式展开(方案 B)**:支持 FTP 控制通道 ↔ 数据通道这种**消息级双向交错**的
  `start_after` 场景(数据通道 `start_after: control.150` + 控制通道 226 报文 `start_after: data`)。
  `plan.Plan` 改为**两段式**——阶段一(`scheduler`)按事件粒度递归+记忆化**只算时刻不发包**:
  每个 flowStart / 每条 message 的 start 与 msgCursor / flowEnd 都是独立事件,各自只依赖其引用的事件,
  被引事件先算出、引用方后算,FTP 式 `control.150 → data → control.226` 在事件粒度有向无环故能算通
  (整流粒度会把它压成"互等对方整流先完成"的死锁);阶段二各 flow 拿着已算好的 per-message 起始
  时刻表独立 `flow.Expand`(seq/ack 状态单次展开内连续维护)。事件依赖图(`scenario.StartAfterGraph`)
  由 `validateStartAfter` 与 plan 的算时阶段共用(`BuildStartAfterGraph`),避免两包重复实现图逻辑;
  真环(跨流消息级互引)仍由校验阶段三色 DFS 拦截。`flow.Expand` 的 `schedule` 参数注入 per-message
  起始时刻;无跨流依赖时退化为 `resolve` 回调路径,行为与历史逐字节等价。
- **未实现 / 简化**:flow 的 overlap / 重传 / IP 分片未做(乱序与段间 RTT 已由 `message.offset_time` /
  `segment.interval` 覆盖);
  畸形开关 `fix_lengths` / `checksum` **解析但忽略**(build 时 `slog.Warn`),真正的畸形 / 原始字节兜底待做;
  HTTP 头按 key 排序输出(未保留原序)。

> **源码组织**:builder 与 scenario 包已按职责拆分。`builder/dns.go` 留构包逻辑(buildDNS/buildDNSRR*/
> dnsName*/dnsRawLayer),`builder/dns_enum.go` 收纯字符串↔枚举映射(dnsType/dnsClass/dnsOpCode/dnsRCode/
> dnsQR/parseDNSRRNumber/validateDNSName)。scenario 包拆为 types.go(顶层结构体与 Hex/PayloadHex)、
> time.go(AbsTime/Offset)、layer_fields.go(各层 *Fields)、layer_decode.go(Layer 解码分发)、
> scenario.go(Load/Validate/Warnings)、start_after_graph.go、ftp_consistency.go、describe.go(见 doc.go)。
> 测试按「一一对应 + 公共辅助集中」组织,详见下文「测试文件命名规约」。

## 核心数据流

```
scenario.yaml
   │  scenario 层:解析 + 校验(尽早失败,报错带字段路径)
   ▼
Scenario(Packets + Flows,每个 packet = 有序 layer 栈)
   │  flow 层:把 flows 展开成 stack 包(补全握手 / seq/ack,不含时间)
   │  plan 层:packets 与 flows 汇流 -> []PlannedPacket{ Stack; Time },按 Time 稳定排序
   ▼
[]PlannedPacket(已带显式时间戳、已排序)
   │  builder 层:有序层栈(外→内)-> gopacket layers;自动串接 next-proto,可原始字节兜底
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
不是特例,只是 `messages` 列表更长。展开器负责在前插握手、后插挥手;每条消息在最后一段后
+1ms 插一个对端 ACK(当前硬编码,未做 delayed-ACK / 可配策略)。

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
segment: { mss: 8, interval: "+10ms" }
#           小段    段间间隔(缺省 1ms;显式给出模拟慢速分段/RTT)
```

`mss` 为切段大小,`interval` 为各数据段间时间间隔。`order`(乱序)/ `overlap`(重叠)/
`retransmit`(重传)**尚未实现**——写入会在解析阶段被拒(未知字段校验)。检测设备的**重组能力**是主战场。

### 时间编排与汇流(已实现)

`internal/plan.Plan` 是 packets 与 flows 的汇流点:把 standalone packets 与各 flow 展开后的
`PlannedPacket{ Stack []Layer; Time time.Time }` 汇流成列表,按 `Time` **稳定排序**后再交
`builder.BuildPlanned` 序列化、`writer` 落盘。`flow.Expand(f, anchor)` 接收流起始锚、自管时间轴,
直接产出 `[]scenario.PlannedPacket`(已带 Time);plan 只负责汇流 + 稳定排序,不再为 flow 内部包
分配时间。时间语义为「**相对上一包 + 跨流独立**」——各 `offset_time` 的参照点因字段而异:

- **跨流独立(flow)**:每条 flow 的 `anchor=base+flow.offset_time`(无 offset 则 = base),plan 不夹紧、不读
  packet 游标、不推进它——无 offset 的多条 flow 在 `base` **并发**(模拟浏览器多连接并行);想顺序就显式
  给递增 offset。flow 内部也不再推导跨流接续。
- **相对上一包(packet)**:`packet.offset_time` 相对**上一包**(第一包相对 `base`);无 offset 则接续默认游标
  (+1ms)。即每包 = 上一包 + offset(或 +1ms),SYN 扫描等"按间隔发包"场景由此表达。
- **相对上一条消息(message)**:flow 内单游标 `msgCursor`(= 上一条消息末尾),每条消息 `start = msgCursor +
  offset`(无 offset 则紧接 `msgCursor`);第一条消息的"上一条"= 握手完成后(`msgAnchor`)。offset>=0 天然
  单调、无需夹紧,慢响应自然拖慢下一条请求(正常非流水线 HTTP)。挥手接在 `msgCursor` 之后(传完才关)。
- 段间按 `segment.interval` 间隔(缺省 `flow.DefaultStep`=1ms);对端 ACK 是伴生控制包,用 `DefaultStep`,
  不被数据段节奏传染。未显式定时时每包 `flow.DefaultStep`(1ms)。

时间表达(由 `AbsTime` / `Offset` 两个类型分别解析,结构性保证取值合法):

- `base_time`:场景里唯一的绝对锚(`AbsTime`,仅 ISO8601,UTC);缺省=确定性 2020 基准。它是各时间链的起点(flow 锚、第一包/第一条消息的"上一项")。写 `+1s` 这类偏移在解析阶段即失败。
- 所有 `Offset` 字段(`packet/flow/message.offset_time`、`segment.interval`)**只接受非负时长**;负值在解析阶段即失败——负偏移通常意味着 `base_time` 选错了起点(应把 `base_time` 提前,而非用负 offset 够到零点之前)。
- `packet.offset_time`:该包相对**上一包**的时长偏移(`Offset`,如 `+1.5s`/`+500ms`/`0s`);该包时刻 = `上一包时刻 + offset`(第一包 = `base + offset`)。缺省则接续默认游标(+1ms)。
- `flow.offset_time`:流起始相对流锚基准的时长偏移,即 `anchor = 流锚基准 + flow.offset_time`。**流锚基准语境相关**:无 `start_after` 时为 `base_time`(缺省则 `anchor=base`,跨流独立、并发,不接续别的 flow / 不读 packet 游标);置 `start_after` 时为被引消息的整组完成时刻(msgCursor)。缺省 `offset_time`=0(紧接 `base` 或被引 msgCursor)。
- `flow.start_after`:可选,形如 `"flow名"`(该 flow 整流结束,挥手后)或 `"flow名.message_id"`(该消息整组完成,msgCursor),置则本 flow 锚基准 = 被引时刻,`anchor = 被引时刻 + flow.offset_time`(缺省 0 紧接)。用于"一个 flow 在另一个 flow / 另一个 flow 某消息完成后开始"(如 FTP 控制通道触发数据通道)。这是**显式跨流依赖**(opt-in),默认独立性不变;plan 多遍拓扑展开(被引 flow 先展开登记时刻,引用方多遍解析),循环依赖在校验阶段(`validateStartAfter` 三色 DFS)拦截。被引 message 须在该 flow 内有唯一 `message_id`;被引 flow 须具名且唯一。被引 flow 可声明在后(拓扑序,非声明序)。
- `message.start_after`:可选,同形 `"flow名"` 或 `"flow名.message_id"`,置则该消息起点 = 被引时刻 + `message.offset_time`(缺省 0 紧接),取代默认的"上一条消息末尾 + offset"。用于"某条消息在另一个 flow / 另一个 flow 某消息完成后才开始"(比 flow 级更细:不必把整条 flow 的握手都推迟,只让某一条消息等跨流事件)。**禁止同流自引**(流内顺序由 message 链式游标保证);被引 flow 须具名且唯一、被引 message 须有唯一 `message_id`,可声明在后(拓扑序)。循环检测仍是 flow 粒度:同 flow 内多条 message 各自 start_after 不同被引 flow,该 flow 整体视作依赖这些被引 flow(建边 = `f.Name → refFlow`)。
- `message.offset_time`:单条消息起始相对**上一条消息末尾**的时长偏移(第一条相对握手完成后 = 流锚 `anchor`);把该消息整组(各数据段 + 对端 ACK)锚定到 `上一条末尾 + offset`。链式 delta、天然单调,用于多轮请求间隔(慢响应拖慢下一条)。握手固定 `DefaultStep` 不参与定时,故第一条消息的 offset 从握手结束算起,避免小 offset 与握手包撞时间。
- `segment.interval`:同一消息各数据段之间的时间间隔(`Offset`,如 `+10ms`);缺省 1ms,显式给出模拟慢速分段 / RTT。只作用于数据段;对端 ACK 用 `DefaultStep`(伴生控制包,不被数据段节奏传染)。

**默认时间策略**:未显式定时的 standalone packet 从 `base_time` 起每 1ms 一个(第一包落 `base`,后续 +1ms);
未显式定时的 flow 在 `base` 起步(并发);未显式定时的 message 紧接上一条末尾。同 `Time` 的包保持声明/合并
顺序(稳定排序),全程不用 `time.Now()`。

> 后续若要更通用的封装 stack 反转或外层/内层分片,可在 `PlannedPacket` 之上再加
> `PlannedPacket{ Stack []Layer; Time time.Time }` 之外的中间态;当前已支持多流按显式时间戳交织。

### 约束

- **确定性**:时间戳由 `base_time` + 显式偏移(或默认 `base + 全局序号*1ms`)派生,seed 控制乱序/抖动,不用 `time.Now()`(保持 golden 可比对)。
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
- **时间编排**:`base_time`(唯一绝对锚,`AbsTime`,仅 ISO8601 如 `2024-01-01T00:00:00Z`,缺省=确定性 2020 基准)、
  `packet.offset_time`、`flow.offset_time`(`Offset`,非负时长,如 `+1.5s`/`+500ms`)可选。
  flow 内部还支持 `message.offset_time`(相对上一条消息,锚定单条消息整组)、
  `segment.interval`(同消息各数据段间隔,缺省 1ms;只作用于数据段,对端 ACK 用默认步长)。
  时间语义为「相对上一包 + 跨流独立」:`packet.offset_time` 相对**上一包**(第一包相对 base,无 offset 则 +1ms);
  `flow.offset_time` 相对 **base**(各 flow 独立、无 offset 则 `base` 并发);
  `message.offset_time` 相对**上一条消息**(第一条相对握手完成后),链式 delta、天然单调无需夹紧。
  按 `Time` 稳定排序后写盘;`base_time` 只能是绝对时刻(由 `AbsTime` 类型保证)。
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

## 测试文件命名规约

1. **一一对应**:`xxx.go` ↔ `xxx_test.go`;不写看不出归属的 `load_test.go` / `payload_hex_test.go` 这类名字。
   已拆分的示例:`scenario/time.go` ↔ `scenario/time_test.go`、`builder/dns.go` ↔ `builder/dns_test.go`、
   `builder/dns_enum.go`(纯枚举映射,无对应测试文件时与 dns_test 共测)、`plan/plan.go` ↔ `plan/plan_test.go`。
2. **公共测试辅助单独放 `helpers_test.go`**:跨多个测试文件复用的 `genPcap` / `buildPackets` / `readPackets` /
   `mustAbs` / `mustOffset` / 栈构造器等集中在 `helpers_test.go`,不要在每个测试文件里复制。
   (若需被非 `_test` 文件引用则命名为 `testing.go`。)
3. **集成 / golden 测试可保留跨文件命名**(如 `examples_test.go`、`ftp_interleave_test.go`),
   但需在文件注释顶部写明覆盖范围。

## 新增一个协议的步骤(清单)

1. `internal/builder/` 加该协议的构造助手(优先复用 gopacket 现成 layer);新协议单独成文件(`proto.go`),与 `builder.go` 的层派发解耦。
2. `internal/scenario/` 加该协议的 schema 结构体 + 校验规则。
3. `internal/builder/` 接线:scenario 字段 → layer;暴露畸形开关(关闭 fix/checksum、raw 注入)。
   **若是封装层**,还须实现 next-proto/ethertype 的自动推导,并允许逐层显式覆盖。
4. `examples/<协议>/` 加一个规范用例 + 一个畸形用例(单职责、小而聚焦);**封装/隧道层再加一个嵌套用例(如 QinQ / GRE 套接)**。
5. 加 golden 测试并生成基准;`go test -race ./...` 通过。
6. README/示例文档同步。
