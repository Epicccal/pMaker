# tcp —— TCP 层(L4)

standalone `packets` 与 `flows` 均用。在 flow 里由 `tcp_session` + `messages` 驱动
握手 / 挥手 / seq-ack 自动推导。通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - tcp:  { sport: 49152, dport: 80, flags: [SYN], seq: 1000 }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `sport` | uint16 | 是(**且非 0**) | 源端口 |
| `dport` | uint16 | 是(**且非 0**) | 目的端口 |
| `flags` | []string | 否 | `SYN` `ACK` `PSH` `FIN` `RST` `URG`(大小写不敏感);不写=全 0 |
| `seq` | uint32 | 否 | 显式序列号;flow 中由展开器推导,无需写 |
| `ack` | uint32 | 否 | 显式确认号;flow 中由展开器推导,无需写 |
| `client_isn` | uint32 | 否 | **仅 flow**:客户端初始 seq |
| `server_isn` | uint32 | 否 | **仅 flow**:服务端初始 seq |
| `mss` | uint16 | 否 | SYN 通告的 MSS option(kind=2)。**不参与切段**,见下节 |
| `checksum` | `Hex` | 否 | 两态覆盖:不写=自动计算(伪首部绑就近 IP);写值=原样上 wire |
| `header_length` | `Hex` | 否 | 两态覆盖(DataOffset,4 位,0-15):不写=自动计算;写值=原样上 wire。5-15 是规范范围,0-4 是合法畸形值 |

## `tcp.mss` 与 `message.segment.mss` 是两回事

| | `tcp.mss` | `message.segment.mss` |
|---|---|---|
| 含义 | 握手时**通告**的 MSS option | 应用层字节的**实际切段大小** |
| 作用 | 只写进 SYN / SYN,ACK 的 option | 决定一条 message 切成几个 TCP 段 |
| 缺省 | 不写 = SYN 不带 MSS option | 不写 = **整条不切**,一条 message 一个段 |

两者**互不影响**:写了 `tcp.mss: 1460` 也不会让 message 按 1460 切段。
**两者不相等是合法且常用的构造**(通告 1460 却按 8 字节切段 = 模拟慢速客户端 / 测重组与规避),
不要为了"一致"去改写用户给的值。写了 `mss` 会给 SYN 加 4 字节 option,自动 `header_length` 因此是 6。

## 组合规则(硬错)

- `sport` / `dport` 必须显式非 0。
- `flow.stack` 里不能写 `checksum` / `header_length`(flow 展开器重建各层字段);这类畸形走 `packets`。
- `flow.stack` 必须同时含 `eth` + 恰好一个网络层 + `tcp` + `tcp_session`。

## 静默陷阱

- **端口 0 构造不出来**:`sport: 0` 被当成"没写"而报错。要构造 0 端口的包,整段走 `payload_hex`。
- **窗口大小恒为 65535**,不开放字段;零窗口探测等场景无法结构化构造。
- **不开放的字段**:urgent pointer、reserved 位、除 MSS 外的一切 option(SACK、时间戳、窗口缩放、NOP 填充)。
- `flags` 写错名字(如 `[SYNACK]`)在 `generate_yaml` 阶段**不报错**,`generate_pcap` 才报
  `未知 TCP flag`。校验阶段只查端口与覆盖值范围。
- 覆盖 `header_length` 会给整包关掉 `FixLengths`,同包其它层的自动长度也随之失效。
- 重传 / 乱序 / 重叠段是 **flow 未实现**特性,不是可写的字段;当前只能用 `packets` 逐包手写
  seq 来伪造(见 `pmaker://schema/overview`)。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 错误校验和 | `checksum: 0xdead` |
| 非法数据偏移(声称头比实际短) | `header_length: 0x0` |
| 非法标志组合(SYN+FIN、SYN+RST) | `flags: [SYN, FIN]` |
| 全 0 标志 / NULL 扫描 | 不写 `flags` |
| 重叠段、重传、乱序 | `packets` 逐包写 `seq`,自己铺字节偏移 |
| SACK / 时间戳 option、非零 urgent、0 端口 | 无字段,整段 `payload_hex` |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `需要 sport 与 dport` | 两个端口都要显式写且非 0。要构造 0 端口的畸形包,整段走 `payload_hex` |
| `tcp.header_length 超出 4 位` | DataOffset 只有 4 位,合法覆盖值 `0x0`-`0xF`(单位 4 字节) |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { dport: 80, flags: [SYN] }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 2, header_length: 0x10 }
```

## 相关

`pmaker://schema/tcp_session`、`pmaker://schema/udp`、`pmaker://schema/overview`(flow / segment / 时间编排)
