# tcp —— TCP 层(L4)

standalone packet 与 flow 均用。flow 中由 `tcp_session` + `messages` 驱动握手/挥手/seq-ack。

```yaml
- tcp: { sport: 49152, dport: 80, flags: [SYN], seq: 1000, ack: 0, client_isn: 1000, server_isn: 5000, mss: 1460 }
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `sport` | uint16 | 是 | 源端口 |
| `dport` | uint16 | 是 | 目的端口 |
| `flags` | []string | 否 | 标志位,如 `[SYN]`/`[SYN,ACK]`/`[FIN,ACK]`/`[RST]` |
| `seq` | uint32 | 否 | 显式序列号(flow 自动推导时无需写) |
| `ack` | uint32 | 否 | 显式确认号(flow 自动推导时无需写) |
| `client_isn` | uint32 | 否 | flow 用:客户端初始 seq |
| `server_isn` | uint32 | 否 | flow 用:服务端初始 seq |
| `mss` | uint16 | 否 | SYN 通告的 MSS option(flow 展开器仅在 SYN 上设)。**不参与应用层切段**,详见下文 |
| `checksum` | `Hex` | 否 | 两态覆盖:不写=自动计算(伪首部绑就近 IP);写值=关闭自动计算,值原样上 wire |
| `header_length` | `Hex` | 否 | 两态覆盖(数据偏移/DataOffset,4 位,可写入 0-15):不写=自动计算;写值=原样上 wire(构造畸形偏移)。上限 `0xF`,`0x10+` 会在校验阶段被拒;其中 5-15 仅是规范 TCP 头长度范围,0-4 为合法畸形值 |

## `tcp.mss` 与 `message.segment.mss` 是两回事

| | `tcp.mss` | `message.segment.mss` |
|---|---|---|
| 含义 | 三次握手时**通告**的 MSS option(kind=2) | 应用层字节的**实际切段大小** |
| 作用范围 | 只写进 SYN / SYN,ACK 的 option 字段 | 决定一条 message 切成几个 TCP 段 |
| 缺省 | 不写 = SYN 不带 MSS option | 不写 = **整条不切**,一条 message 一个段 |

两者**互不影响**:写了 `tcp.mss: 1460` 也不会让 message 按 1460 切段,切段只由 `segment.mss` 驱动。

- **要切段就得显式写 `segment.mss`。** 大 body(尤其 `@file` 注入的文件)不写会撑爆 IP 长度字段并静默回绕,见 `pmaker://schema/overview` 的「单段字节上限」。取值通常与 `tcp.mss` 一致。
- **两者不相等是合法且常用的构造**,不是错误:通告 1460 却按 8 字节切段,正是模拟慢速客户端 / 测试重组与规避的标准手法(见 `examples/http/slow_second.yaml`)。**不要**为了"一致"去改写用户给的值。

另外,`mss` 会给 SYN 包加 4 字节 option,自动计算的 `header_length` 因此是 6 而非 5。

## checksum 伪首部

TCP checksum 自动绑定**就近 IP 层**(多层 IP 时绑内层)。除非故意要错 checksum,无需手算。显式写 `checksum`/`header_length` 即关闭对应自动计算、原样落值(两态);flow 中暂不支持,请用 standalone packet。
