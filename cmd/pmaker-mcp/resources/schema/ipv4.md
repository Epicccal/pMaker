# ipv4 —— IPv4 层(L3)

网络层。上接 `eth` / `vlan` / `gre`,下接 `tcp` / `udp` / `icmp` / `gre` / 内层 IP。
通则(两态覆盖 / 兜底 / `@file`)见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - tcp:  { sport: 40000, dport: 80, flags: [SYN], seq: 1000 }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `src` | IPv4 字符串 | 是 | 源地址 |
| `dst` | IPv4 字符串 | 是 | 目的地址 |
| `ttl` | uint8 | 否(缺省 64) | 生存时间 |
| `protocol` | **枚举名** | 否 | 覆盖下一层协议号,**只认名字**:`tcp` `udp` `icmp` `icmpv6` `gre` `ipv4` `ipv6` |
| `checksum` | `Hex` | 否 | 两态覆盖:不写=自动计算;写值=关闭自动计算,原样上 wire |
| `total_length` | `Hex` | 否 | 两态覆盖(16 位):不写=自动计算(含头总字节数);写值=原样上 wire |
| `header_length` | `Hex` | 否 | 两态覆盖(IHL,4 位,0-15):不写=自动计算;写值=原样上 wire。5-15 是规范范围,0-4 是合法畸形值 |

next-proto 自动推导:后接 `tcp` → 6、`udp` → 17、`icmp` → 1、`gre` → 47、`ipv4` → 4(IP-in-IP)、
`ipv6` → 41;其余情况(`payload`/`payload_hex`/无下一层)落 6(TCP) 惯例缺省,**其它值一律报错**,
见「静默陷阱」。

## 组合规则(硬错)

- `src` / `dst` 缺一不可;地址**格式**在出包阶段才校验(`generate_yaml` 放行 `src: "300.1.1.1"`,
  `generate_pcap` 才报 `src ip "300.1.1.1" 不是合法 IPv4`)。
- `total_length` / `header_length` 各自独立:只写其一时另一个仍自动计算。
- `header_length` 上限 `0xF`。写 `0x10+` 会被拒 —— 它在 wire 上与 Version 共享一个字节
  (`(Version<<4)|IHL`),溢出会污染版本号。
- **`flow.stack` 上的 `checksum` / `total_length` / `header_length` 覆盖原样透传到每个展开包**
  (每包同值)。length 覆盖在 flow 中会因 inner 载荷逐包变而出软告警;恒定 checksum(如
  VXLAN outer UDP 的 `0x0000`)天然合法。

## 静默陷阱

- **`protocol` 只认上表那几个名字**。写 `protocol: sctp` 或 `protocol: 47`(数字)在
  `generate_pcap` 阶段报错(不再静默变 TCP)。要指定任意协议号,当前没有字段可用,
  只能整段走 `payload_hex` 手拼 IP 头。
- 覆盖 `total_length` / `header_length` 会给**整包**关掉 `FixLengths`:同一个包里其它层
  (如 `udp.total_length`)的自动长度计算也随之失效。要只让一层撒谎,别的层就得自己写死值。
- `link_type` 缺省是 `ethernet`。只写 L3 的包(`- ipv4` 打头,无 `eth`)是合法的,但会被写进声明为
  Ethernet 的 pcap,解析端把 IP 头当 MAC 读。这种包须显式 `link_type: raw`。
- 不开放的头字段:IP ID、DF/MF 标志、分片偏移、Options。分片、`DF` 置位等需求当前只能走
  `payload_hex`(IP 分片是**未实现**特性,不是可覆盖字段)。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 错误校验和 | `checksum: 0xdead` |
| 撒谎的总长度 | `total_length: 9999` |
| 非法 IHL(小于 5,声称头比实际短) | `header_length: 0x0` |
| 解析断链 | `protocol: udp` 但下一层实际写 `tcp` |
| IP 分片 / 非零 IP ID / 带 Options 的头 | 无字段,整段 `payload_hex` |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `ipv4.header_length 超出 4 位` | IHL 只有 4 位,合法覆盖值 `0x0`-`0xF`。想让"头长度"字段撒更大的谎,改用 `total_length`,或整段 `payload_hex` |
| `ipv4.total_length 超出 16 位` | 上限 `0xFFFF`。要构造超长声明只能整段 `payload_hex` |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", header_length: 0x10 }
      - tcp:  { sport: 1, dport: 2 }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", total_length: 0x10000 }
      - tcp:  { sport: 1, dport: 2 }
```

## 相关

`pmaker://schema/ipv6`、`pmaker://schema/gre`、`pmaker://schema/tcp`、`pmaker://schema/payload_hex`
