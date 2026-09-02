# udp —— UDP 层(L4)

无握手、无 seq/ack 的数据报(DNS、QUIC 探测等)。通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.53", ttl: 64 }
      - udp:  { sport: 40000, dport: 53 }
      - dns:  { id: 0x1234, qr: query, questions: [{ name: "example.com", type: A }] }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `sport` | uint16 | 是(**且非 0**) | 源端口 |
| `dport` | uint16 | 是(**且非 0**) | 目的端口 |
| `checksum` | `Hex` | 否 | 两态覆盖:不写=自动计算(伪首部绑就近 IP);写值=原样上 wire。写 `0x0` 在 IPv4 下即 RFC 768 的"不校验" |
| `total_length` | `Hex` | 否 | 两态覆盖(16 位):不写=自动计算(8 字节头 + payload);写值=原样上 wire |

## 组合规则

- `sport` / `dport` 必须显式非 0。
- UDP 的下一层是任意 payload 生产层(`dns` / `payload` / `payload_hex` …),
  IP 层 protocol 会自动推导为 17。
- **flow 目前不支持 UDP**:`flow.stack` 硬性要求 `tcp` + `tcp_session`。多个 UDP 数据报之间的
  时序用 `packets` + `offset_time` 表达。

## 静默陷阱

- **端口 0 构造不出来**:`sport: 0` 被当成"没写"而报错;要 0 端口走 `payload_hex`。
- **IPv6 下 checksum 为 0 是非法的**(RFC 8200 要求 UDP-over-IPv6 必须校验),但工具照写不误、
  不报错也不告警 —— 这是可用的畸形构造点,也是易误踩点。
- 覆盖 `total_length` 会给整包关掉 `FixLengths`,同包 IP 层的自动长度也随之失效。
- UDP 无分片能力:超 MTU 的大 payload 会照常生成一个巨包,工具不做 MTU 检查、不自动分片。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 错误校验和 | `checksum: 0xdead` |
| 声明"不校验"(IPv4 合法 / IPv6 非法) | `checksum: 0x0` |
| 撒谎的 UDP 长度(小于实际、超长) | `total_length: 0x8` / `total_length: 9999` |
| 0 端口、IP 分片 | 无字段,整段 `payload_hex` |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `需要 sport 与 dport` | 两个端口都要显式写且非 0。要构造 0 端口的畸形包,整段走 `payload_hex` |
| `udp.total_length 超出 16 位` | 上限 `0xFFFF`(UDP 长度字段就是 16 位) |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 53 }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 1, dport: 2, total_length: 0x10000 }
```

## 相关

`pmaker://schema/dns`、`pmaker://schema/tcp`、`pmaker://schema/ipv4`
