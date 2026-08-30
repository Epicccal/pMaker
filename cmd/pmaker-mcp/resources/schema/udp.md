# udp —— UDP 层(L4)

无握手、无 seq/ack,适合 DNS、QUIC 探测等一串数据报。flow 中也可用(退化情形)。

```yaml
- udp: { sport: 5353, dport: 5353 }
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `sport` | uint16 | 是 | 源端口 |
| `dport` | uint16 | 是 | 目的端口 |
| `checksum` | `Hex` | 否 | 两态覆盖:不写=自动计算(伪首部绑就近 IP);写值=关闭自动计算,值原样上 wire(`0` 在 IPv4 下表示「不校验」,RFC 768 合法) |
| `total_length` | `Hex` | 否 | 两态覆盖:不写=自动计算(头 8 + payload);写值=原样上 wire(构造撒谎长度) |

## checksum 伪首部

UDP checksum 自动绑定**就近 IP 层**(多层 IP 时绑内层)。除非故意要错 checksum,无需手算。显式写 `checksum`/`total_length` 即关闭对应自动计算、原样落值(两态);flow 中暂不支持,请用 standalone packet。
