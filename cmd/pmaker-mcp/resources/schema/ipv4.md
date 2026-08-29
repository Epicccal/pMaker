# ipv4 —— IPv4 层(L3)

```yaml
- ipv4: { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64, protocol: gre, checksum: 0xdead, fix_lengths: false }
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `src` | IPv4 字符串 | 是 | 源地址 |
| `dst` | IPv4 字符串 | 是 | 目的地址 |
| `ttl` | uint8 | 否 | 缺省由 gopacket 给定 |
| `protocol` | string | 否 | 显式覆盖下一层协议(`tcp`/`udp`/`gre`/`ipv4`);自动推导时无需写 |
| `checksum` | `Hex` | 否 | 三态覆盖:不写=自动计算;写值=关闭自动计算,原样上 wire(构造错误 checksum);`0` 也照单全收 |
| `fix_lengths` | bool | 否 | 畸形开关:`false` 关闭自动长度修正(当前解析但构建时告警忽略) |

## next-proto 串接

- 后接 `tcp` → protocol=6;`udp` → 17;`gre` → 47;`ipv4` → 4(隧道)
- 显式 `protocol` 制造断链;`checksum` 三态覆盖制造错误 checksum;`fix_lengths` 仍解析但忽略(独立一轮做)
