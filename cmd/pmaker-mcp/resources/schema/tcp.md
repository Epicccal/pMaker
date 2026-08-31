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
| `mss` | uint16 | 否 | SYN 通告的 MSS option(flow 展开器仅在 SYN 上设) |
| `checksum` | `Hex` | 否 | 两态覆盖:不写=自动计算(伪首部绑就近 IP);写值=关闭自动计算,值原样上 wire |
| `header_length` | `Hex` | 否 | 两态覆盖(数据偏移/DataOffset,4 位,可写入 0-15):不写=自动计算;写值=原样上 wire(构造畸形偏移)。上限 `0xF`,`0x10+` 会在校验阶段被拒;其中 5-15 仅是规范 TCP 头长度范围,0-4 为合法畸形值 |

## checksum 伪首部

TCP checksum 自动绑定**就近 IP 层**(多层 IP 时绑内层)。除非故意要错 checksum,无需手算。显式写 `checksum`/`header_length` 即关闭对应自动计算、原样落值(两态);flow 中暂不支持,请用 standalone packet。
