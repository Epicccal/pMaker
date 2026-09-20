# ipv6 —— IPv6 层(L3)

网络层。字段与 `ipv4` 一一对应但命名不同(`hop_limit` / `next_header` / `payload_length`)。
通则(两态覆盖 / 兜底 / `@file`)见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv6: { src: "2001:db8::1", dst: "2001:db8::2", hop_limit: 64 }
      - tcp:  { sport: 40000, dport: 80, flags: [SYN], seq: 1000 }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `src` | IPv6 字符串 | 是 | 源地址 |
| `dst` | IPv6 字符串 | 是 | 目的地址 |
| `hop_limit` | uint8 | 否(缺省 64) | 跳数限制(对应 IPv4 的 `ttl`) |
| `traffic_class` | uint8 | 否 | 流量类别 |
| `flow_label` | uint32 | 否 | 流标签 |
| `next_header` | **枚举名** | 否 | 覆盖下一层协议号,**只认名字**:`tcp` `udp` `icmp` `icmpv6` `gre` `ipv4` `ipv6` |
| `payload_length` | `Hex` | 否 | 两态覆盖(16 位):不写=自动计算(**不含** 40 字节固定头);写值=原样上 wire |
| `mtu` | int | 否 | 自动分片开关:超过时在主头后插入 Fragment 扩展头(next_header=44),分片 ID 由确定性计数器分配(不可指定)。不写 = 永不分片。与 `payload_length` 互斥 |

next-header 自动推导:后接 `tcp` → 6、`udp` → 17、`icmpv6` → 58、`gre` → 47、`ipv6` → 41;
其余情况(`payload`/`payload_hex`/无下一层)落 6(TCP) 惯例缺省,**其它值一律报错**,见「静默陷阱」。

## 组合规则(硬错)

- `src` / `dst` 缺一不可;**必须是真 IPv6**,`src: "10.0.0.1"` 会在出包阶段报
  `src ip "10.0.0.1" 不是合法 IPv6`(`generate_yaml` 阶段放行)。
- IPv6 无头部校验和,故本层**无 `checksum` 字段**;上层 TCP/UDP/ICMPv6 的校验和照常绑 IPv6 伪首部。
- 无 `header_length`(IPv6 固定 40 字节头)。
- `flow.stack` 里不能写 `payload_length`(length 覆盖在 flow 中被拒),这类畸形走 `packets`。
- `flow.stack` 的网络层 `ipv4` / `ipv6` 二选一,不能同时出现。
- `mtu` 与 `payload_length` **同层互斥**。下限 56(40 主头 + 8 Fragment 头 + 一片 8 字节
  对齐载荷),低于即硬错;同一 stack 内两层 IP(隧道内外)同时写 `mtu` 也硬错 ——
  写在哪层就分哪层,只能写一层。

## 静默陷阱

- **`next_header` 只认上表那几个名字**。写 `next_header: 43`(Routing 扩展头)或
  `next_header: hopopt` 在 `generate_pcap` 阶段报错(不再静默变 TCP)。
- 扩展头(Hop-by-Hop、Routing、Destination Options)**完全未实现**。`mtu` 自动分片
  会插入 Fragment 扩展头(next_header=44),ID / M 位 / 偏移由切片器分配,**不可指定**;
  手工扩展头链、畸形分片只能整段 `payload_hex` 手拼。
- 覆盖 `payload_length` 会给整包关掉 `FixLengths`,同包其它层的自动长度也随之失效。
- `payload_length` 的自动值**不含** 40 字节固定头 —— 与 `ipv4.total_length`(含头)相反,
  手写覆盖值时别照搬 IPv4 的算法。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 撒谎的载荷长度 | `payload_length: 9999` |
| 解析断链 | `next_header: udp` 但下一层实际写 `tcp` |
| 扩展头链 / IPv6 分片 | 无字段,整段 `payload_hex` |
| 错误的上层校验和 | 写在 `tcp` / `udp` / `icmpv6` 的 `checksum` 上 |

## 一致性告警(软告警,非硬错)

| code | 触发 | 说明 |
|------|------|------|
| `ipv6.mtu-below-minimum` | `mtu` < 1280(RFC 8200 最小链路 MTU) | 照常分片(`mtu` ≥ 结构下限 56 即可),仅提示真实链路通常不出现此值;极端小 MTU 测试场景可忽略 |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `ipv6.payload_length 超出 16 位` | 上限 `0xFFFF`(IPv6 载荷长度就是 16 位)。Jumbogram(RFC 2675,长度 0 + Hop-by-Hop 选项)当前不支持,走 `payload_hex` |
| `网络层(ipv4 或 ipv6)不可同时出现` | flow.stack 同一段内 ipv4/ipv6 二选一。跨段的版本异构(IPv6 underlay + IPv4 overlay)用一层 `vxlan` 表达 |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv6: { src: "2001:db8::1", dst: "2001:db8::2", payload_length: 0x10000 }
      - tcp:  { sport: 1, dport: 2 }
```

```yaml-bad
link_type: ethernet
flows:
  - name: f
    stack:
      - eth:         { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:        { src: "10.0.0.10", dst: "10.0.0.80" }
      - ipv6:        { src: "2001:db8::1", dst: "2001:db8::2" }
      - tcp:         { sport: 49152, dport: 80 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - payload: { payload: "hi" }
```

## 相关

`pmaker://schema/ipv4`、`pmaker://schema/icmpv6`、`pmaker://schema/tcp`、`pmaker://schema/payload_hex`
