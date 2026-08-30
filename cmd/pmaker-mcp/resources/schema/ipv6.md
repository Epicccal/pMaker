# ipv6 —— IPv6 层(L3)

```yaml
- ipv6: { src: "2001:db8::1", dst: "2001:db8::2", hop_limit: 64, traffic_class: 0, flow_label: 0, next_header: tcp }
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `src` | IPv6 字符串 | 是 | 源地址 |
| `dst` | IPv6 字符串 | 是 | 目的地址 |
| `hop_limit` | uint8 | 否 | 跳数限制(类比 IPv4 ttl),缺省 64 |
| `traffic_class` | uint8 | 否 | 流量类别 |
| `flow_label` | uint32 | 否 | 流标签 |
| `next_header` | string | 否 | 显式覆盖下一层协议(`tcp`/`udp`/`icmpv6`/`ipv4`/`ipv6`);制造断链用 |
| `payload_length` | `Hex` | 否 | 两态覆盖:不写=自动计算(载荷字节数,不含 40B 头);写值=原样上 wire(构造撒谎长度) |

## next-proto 串接

后接 `tcp` → 6;`udp` → 17;`icmpv6` → 58;显式 `next_header` 制造断链。`payload_length` 两态覆盖构造撒谎长度。
