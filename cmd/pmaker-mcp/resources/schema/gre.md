# gre —— GRE 隧道封装(L3,RFC 1701/2784/2890)

隧道层:外层 IP 之后再套一整个内层报文,**可递归**;支持 standalone `packets` 与
`flows`(flow 中 gre 是隧道切点,见「flow 用法」)。头**变长**:前 4 字节固定,
后续字段由标志位决定存在与否(基础 4 字节,C/K/S/A 每置位一位 +4,最长 20 字节)。通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "1.1.1.1", dst: "2.2.2.2", ttl: 64 }              # 外层,protocol 自动 = 47
      - gre:  { key: 0x0000a10b }                                       # K=1,8 字节头
      - ipv4: { src: "192.168.1.1", dst: "192.168.1.2", ttl: 64 }       # 内层 IP
      - tcp:  { sport: 1234, dport: 443, flags: [SYN] }
```

## 字段

可选字段全部**写即置位**(`key` 写 → K=1),不引入并行的 `*_present` 开关;
`checksum` 例外走三态(见下)。可选字段未写 = 对应标志位 0、字段字节不存在。

| 字段 | 类型 | 缺省 | 说明 |
|------|------|------|------|
| `protocol` | Hex(16 位) | 按内层推导 | Protocol Type。表外值(PPTP `0x880B`、ERSPAN `0x88BE`/`0x22EB`、MPLS `0x8847`)与断链畸形须显式写 |
| `key` | Hex(32 位) | 不落 | 写即 K=1(RFC 2890)。NVGRE 为 VSID(24)\|FlowID(8),PPTP v1 为 PayloadLength(16)\|CallID(16) |
| `seq` | uint32 | 不落 | 写即 S=1(RFC 2890)。flow 不代为递增(见「flow 用法」) |
| `checksum_present` | bool | `false` | C 位。`true` = C=1 且 checksum 自动算(RFC 2784);`false` = 不写该字段 |
| `checksum` | Hex(16 位) | 不落 | 两态:写即隐含 C=1 且原样落值(畸形);与 `checksum_present: true` 并存时以值为准 |
| `offset` | Hex(16 位) | 不落 | Reserved1(规范值 0),仅 C=1 时上 wire |
| `version` | uint8(0-7) | `0` | 0=标准(RFC 2784)/ 1=PPTP(RFC 2637) |
| `ack` | uint32 | 不落 | 写即 A=1(仅 PPTP v1,RFC 2637 §4.1) |
| `recursion` | uint8(0-7) | `0` | Recur(RFC 1701 规范值 0) |
| `flags` | uint8(**0-15**) | `0` | 保留位。上限 15 而非 RFC 1701 的 31:第 5 位与 Ack 标志位重叠(见「静默陷阱」) |

不开放:routing / SRE 与 `s` 位(RFC 2784 已废弃 + gopacket 序列化缺陷,见
`pmaker://schema/_why_gre_no_routing`)、长度字段(GRE 头无载荷长度字段)。

## 组合规则

- **`gre` 前一层必须是 `ipv4`/`ipv6`**(GRE 由 IP 协议 47 承载,自动推导);内层可以是
  任意完整栈,包括再来一层 `gre`(多重隧道,但 flow 里一层隧道一个切点)。
- **Protocol Type 推导**(按内层第一层):`ipv4` → `0x0800`、`ipv6` → `0x86dd`、
  `eth` → `0x6558`(TEB);内层为其他层(udp/icmp 等)**报错**,仅 payload/payload_hex
  与末层兜底缺省 0x0800;表外值(0x880B 等)显式写 `protocol` 覆盖。
- **头长规则**(golden 依据):基础 4 字节,C/K/S/A 每置位一位 +4 字节,组合任意
  (4/8/12/16/20 字节,如 C+K+S+A 全置 = 20)。字段序:Checksum → Offset(Reserved1)→
  Key → Seq → Ack。
- 内层 TCP/UDP 的校验和伪首部绑定**内层 IP**(就近绑定),不是外层。
- checksum 覆盖范围 = GRE 头 + 全部载荷(RFC 2784 §2.1),与 ipv4/tcp/udp 同一套两态机制。
- **flow 用法**:`flow.stack` 把 `gre` 当隧道切点(与 vxlan 并列),细则见下方「flow 用法」节。

## 一致性告警(软告警,非硬错)

| code | 触发 | 说明 |
|------|------|------|
| `gre.reserved-nonzero` | version=0 下 `recursion`/`flags` 非零,或 C=1 时 `offset` 非零 | RFC 1701 规定 bits 5-12 MUST 传零(发送侧义务,收端 ignore,**不是**「收端会丢包」—— RFC 2784 的 MUST discard 只管 bits 1-5);RFC 2784 §2.1 规定 Reserved1 若存在 MUST 传零。故意构造可忽略 |
| `gre.version-unknown` | `version` ∈ 2-7 | RFC 2784 规定 Version MUST 为 0(1 是 RFC 2637 PPTP 的合法扩展);照常出包,收端大概率丢弃 |
| `gre.pptp-missing-key` | `version: 1` 且未写 `key` | RFC 2637 §4.1 要求 K 位置 1;高 2 字节=Payload Length、低 2 字节=Call ID |
| `gre.ack-outside-v1` | version ≠ 1 时写 `ack` | Acknowledgment Number 由 RFC 2637 定义,version=0 无此字段;确属故意可忽略 |
| `gre.nvgre-missing-key` | **显式**写 `protocol: 0x6558` 且未写 `key` | RFC 7637 要求 K=1(Key=VSID\|FlowID);内层 eth **自动推导**出 0x6558 的 TEB 桥接不告警(RFC 1701 不要求 Key),只认显式 NVGRE 声明 |

## 静默陷阱

- **`flags` 值域是 0-15,不是 RFC 1701 的 0-31**(写 ≥16 硬错):gopacket 把 Flags 的
  第 5 位编到与 Ack 相同的 bit 上,≥16 会静默点亮 A 位、凭空多出 4 字节 Ack 字段。
  15 以内恰是 RFC 2637 Flags(bits 9-12)全集,卡住无损;要构造全 5 位保留位请用
  `payload_hex` 整段手拼。
- **「标志位置位但字段字节缺失」不可表达**:头长由标志位驱动,置 K 位就必有 4 字节 Key。
  那类纯畸形走 `payload_hex`。
- **PPTP Key 高 2 字节是载荷长度**(不含 GRE 头),要自己算对,不是不透明值;
  flow 场景下载荷逐包变而 key 是模板静态值,PPTP 会话在 flow 下必然不符。
- 隧道叠加会增加头部开销,但工具**不做 MTU 检查**:内外层长度自动计算各自独立,超 MTU 的
  巨包会被照常写进 pcap。
- flow 不代算 GRE `seq`/`ack`:写了会被每包原样落值,而真值逐包变(见「flow 用法」)。

## flow 用法

`gre` 与 `vxlan` 同为 flow 的隧道切点。与 VXLAN 的两点差异:outer 段**无传输层要求**
(GRE 直挂 IP,协议 47;插 udp 也合法,GRE-in-UDP 形态,端口不承载隧道身份;**tcp 硬错**
—— 外层 IPv4 protocol=6 装 GRE 头是静默坏包,畸形隧道请用 standalone packets);
inner 段 **eth 可选**(GRE 直承 IP 时没有,TEB/NVGRE 形态才有)。
反向包内外两层 IP/eth 端点一并交换,GRE 头字段(`key`/`protocol` 等)两向保持声明值。

```yaml
link_type: ethernet
flows:
  - name: gre-http
    stack:
      - eth:   { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }   # outer
      - ipv4:  { src: "1.1.1.1", dst: "2.2.2.2", ttl: 64 }
      - gre:   { key: 0x0000a10b }
      - ipv4:  { src: "192.168.1.10", dst: "192.168.1.20", ttl: 64 }    # inner,无 eth
      - tcp:   { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack: [ { http_request: { method: GET, url: /a } } ]
      - from: dst
        stack: [ { http_response: { status: 200, body: "ok" } } ]
```

UDP 会话同理(inner 段换 `udp` + `udp_session`);NVGRE 形态 inner 段带 `eth`,
protocol 自动推导 0x6558。

约束:outer 段须含 `eth`;一条 flow 只允许一个隧道切点(两层 GRE / GRE 套 VXLAN 走
`packets`);会话层只能在 inner 段;**flow 不代为递增 GRE `seq` / `ack`** —— 写在
flow.stack 里的 `seq`/`ack`/`checksum` 是静态值,真值逐包变,产 `flow.override-static`
软告警(需要真实递增序列请用 standalone packets);`key` 是逐流恒定量,不告警。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 外层 protocol 与实际不符(断链) | 外层 `ipv4: { protocol: udp }` |
| GRE protocol 与内层不符(断链) | `protocol` 显式覆盖,如 `0x86dd` |
| 表外 Protocol Type(PPTP/ERSPAN/MPLS) | `protocol: 0x880B` 等,直接写 16 位裸值 |
| 全 5 位保留位 / 带 Routing 的 GRE 头 | 整段 `payload_hex` 手拼(第 5 位撞 A 位、SRE 链 gopacket 写坏,不开放结构化构造) |
| 内层报文本身畸形 | 正常写内层各层的 `checksum` / `total_length` 覆盖 |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `gre 前一层必须是 ipv4/ipv6` | 在 `gre` 前加 `ipv4`/`ipv6`(GRE 由 IP 协议 47 承载,不能直挂 eth) |
| `gre 切点的外层段不允许 tcp` | flow 的 outer 段把 `tcp` 改成 `udp`(GRE-in-UDP)或删掉(GRE 直挂 IP);GRE-in-TCP 不存在,畸形隧道请用 standalone packets |
| `Hex 字段须为非负整数且不超过 0xFFFFFFFF` | Hex 字段是无符号 wire 值:负数或超 0xFFFFFFFF 解析即报错(不会回绕、不会截断);请写非负十进制或 `0x..` |
| `gre.flags 超出值域 0-15` | 上限 15 而非 RFC 1701 的 31:第 5 位与 Ack 标志位重叠,gopacket 编码会静默点亮 A 位;要构造全 5 位保留位请用 `payload_hex` 整段手拼 |
| `gre.checksum_present: false 与 checksum 并存自相矛盾` | C=0 时 Checksum 字段不上 wire,写了的值落不下去;请去掉 checksum 或置 checksum_present: true |
| `gre.offset: Reserved1 仅在 C=1` | Reserved1 仅 C=1 时上 wire;请置 checksum_present: true 或去掉 offset |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - gre:  { key: 0x1234 }
      - ipv4: { src: "192.168.1.1", dst: "192.168.1.2" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - gre:  { flags: 16 }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - gre:  { checksum_present: false, checksum: 0xdead }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - gre:  { offset: 0x1234 }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - gre:  { key: -1 }
      - ipv4: { src: "192.168.1.1", dst: "192.168.1.2" }
```

```yaml-bad
link_type: ethernet
flows:
  - name: gre-tcp-bad
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "1.1.1.1", dst: "2.2.2.2" }
      - tcp:  { sport: 1234, dport: 80 }
      - gre:  { key: 0x42 }
      - ipv4: { src: "192.168.1.10", dst: "192.168.1.20" }
      - tcp:  { sport: 49152, dport: 80 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack: [ { http_request: { method: GET, url: /a } } ]
```

## 相关

`pmaker://schema/ipv4`、`pmaker://schema/vlan`、`pmaker://schema/payload_hex`、
`pmaker://schema/vxlan`、`pmaker://schema/_why_gre_no_routing`、
`pmaker://examples/tunnel/gre_key.yaml`
