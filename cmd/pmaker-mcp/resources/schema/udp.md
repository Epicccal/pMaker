# udp —— UDP 层(L4)

无握手、无 seq/ack,适合 DNS、QUIC 探测等一串数据报。flow 中也可用(退化情形)。

```yaml
- udp: { sport: 5353, dport: 5353 }
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `sport` | uint16 | 是 | 源端口 |
| `dport` | uint16 | 是 | 目的端口 |

## checksum 伪首部

UDP checksum 自动绑定**就近 IP 层**(多层 IP 时绑内层)。除非故意要错 checksum,无需手算。
