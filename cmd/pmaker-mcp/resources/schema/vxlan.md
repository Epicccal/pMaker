# vxlan —— VXLAN 隧道封装(UDP 承载二层隧道,RFC 7348)

隧道层:`udp`(标准端口 4789)之后再套一个 inner Ethernet 帧。VXLAN 头固定 8 字节。
支持 standalone `packets` 与 `flows`(flow 中 VTEP/VM 端点随方向反转,VNI/UDP 端口两向不变)。
通则见 `pmaker://schema/_conventions`。

典型栈:

```text
eth → ipv4/ipv6 → udp(4789) → vxlan → eth(inner) → [vlan] → ipv4/ipv6 → tcp/udp/payload
```

## 骨架

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:   { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:  { src: "10.0.0.10", dst: "10.0.0.20", ttl: 64 }   # 外层,protocol 自动 = UDP(17)
      - udp:   { sport: 49152, dport: 4789 }                      # VXLAN 标准端口
      - vxlan: { vni: 100 }
      - eth:   { src: "00:22:33:44:55:66", dst: "00:33:44:55:66:77" }  # inner Ethernet(必需)
      - ipv4:  { src: "192.168.1.10", dst: "192.168.1.20", ttl: 64 }
      - tcp:   { sport: 40000, dport: 80, flags: [SYN], seq: 1000 }
```

## 字段

| 字段 | 类型 | 缺省 | 说明 |
|------|------|------|------|
| `vni` | 24 位整数(0-0xFFFFFF) | `0`(建议显式写,利于用例自描述) | VXLAN Network Identifier。`0` 合法(边界用) |
| `valid_id_flag` | bool | `true` | 'I' 位(RFC 7348)。显式 `false` 构造非法 VXLAN 头('I' 位落 0) |

GBP 扩展位('G'/'D'/'A'、Group Policy ID)不作为字段开放;构造带 GBP 位的头走 `payload_hex`
整段手拼。

## 组合规则

- `vxlan` 的**前一层必须是 `udp`**(VXLAN 头由 UDP 承载),**后一层必须是 `eth`**(inner Ethernet
  是必需层)。两者不满足在 `scenario.Validate` 阶段报错。
- inner `eth` 之后可接 `vlan` / `ipv4` / `ipv6` / 传输层 / `payload*`,串接规则同外层
  (inner Ethernet 后接 `vlan` → 0x8100、接 `ipv4` → 0x0800、接 `ipv6` → 0x86dd)。
- 外层 UDP checksum 绑**外层 IP**;内层 TCP/UDP checksum 绑**内层 IP**(就近绑定,与 GRE 内层同机制)。
- **非 4789 目的端口合法**(如 cilium-overlay 的 8472):VXLAN 层不改写 UDP 端口,照常出包。
- **flow 用法(整栈模板)**:`flow.stack` 写完整隧道栈(outer → `vxlan` → inner → `tcp` +
  `tcp_session`),展开器按「写即覆盖、原样落值」把整栈套到每个展开包:反向包(含挥手)outer/inner
  的 eth/ipv4/ipv6 一并交换 src/dst;VNI 与 outer UDP 端口两向保持声明值;seq/ack/flags 由展开器
  推导,不写在 tcp 上。约束:只支持一层 vxlan;outer 段禁止 tcp/tcp_session;outer udp `dport`
  为 0 是硬错(VXLAN 没有承载端口就无法分派)。
- inner `eth` 之后的内容不做进一步校验(`vxlan → eth → eth` 双层 eth 可构造,是字段错位的
  规避流量形态)。

## 静默陷阱

- **outer UDP checksum 缺省计算真实校验和**,与 RFC 7348 §5 的「outer UDP checksum SHOULD 传 0」不同。
  要常见形态(outer IPv4)须显式 `udp: { checksum: 0x0000 }`。**分地址族**:outer IPv4 传 0 是常态;
  outer IPv6 传 0 属 RFC 6935/6936 隧道例外(IPv6 基线禁 0),构造前先确认解析端支持。
  覆盖值原样落值(`0x0000` 恒定值天然正确,无需「每包重算」担忧)。
- **`udp` 漏写 `dport` 会被 validate 拦截为硬错**(`需要 sport 与 dport`);`vni` 漏写静默出 0,无告警(仅本条说明)。
- **非 4789 目的端口照常出包、不告警**,但 gopacket 等标准解析器按 UDP 目的端口分派下一层
  (仅 4789 → VXLAN):非标端口下 inner 栈整体落 `gopacket.Payload`,回读逐层解断链。
  这是故意构造(端口混淆用例)而非错误,生成无任何提示。回读验证要么用支持非标端口的解析器,
  要么按 raw bytes 断言。
- VXLAN 头无长度/checksum 字段,`auto_content_length` 等机制与本层无关;外层 UDP 长度
  由自动计算覆盖(inner 帧全部字节计入 UDP 载荷)。
- 隧道叠加增加头部开销,工具**不做 MTU 检查**(与 GRE 同口径):超 MTU 的巨包照常写进 pcap。
- GBP 位('G'/'D'/'A'、Group Policy ID)恒为 0,不可结构化构造;需要 GBP 置位的头走
  `payload_hex` 手拼 8 字节 VXLAN 头 + inner 帧。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 非法 VXLAN 头('I' 位落 0) | `vxlan: { vni: 100, valid_id_flag: false }` |
| VNI 边界(0 / 0xFFFFFF) | 直接写 `vni: 0` / `vni: 0xFFFFFF` |
| 非标 UDP 端口(设备兼容性) | `udp: { dport: 8472 }` —— 注意回读断链,见「静默陷阱」 |
| VXLAN 头与 inner 帧不符 | 整段 `payload_hex` 手拼 |
| inner 帧本身畸形 | 正常写 inner 各层的 `checksum` / `total_length` 覆盖 |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `vxlan.vni 超出 24 位` | VNI 上限 0xFFFFFF;更大的值走 `payload_hex` 手拼整段(含 8 字节头) |
| `vxlan 前一层必须是 udp` | 在 `vxlan` 前加 `udp`(标准端口 4789);VXLAN 只能由 UDP 承载 |
| `vxlan 后必须紧跟 inner eth` | 在 `vxlan` 后加 inner `eth`(VXLAN 内只能是以太帧);无 inner 帧的裸 VXLAN 头走 `payload_hex` |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:   { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:  { src: "10.0.0.10", dst: "10.0.0.20" }
      - udp:   { sport: 49152, dport: 4789 }
      - vxlan: { vni: 16777216 }
      - eth:   { src: "00:22:33:44:55:66", dst: "00:33:44:55:66:77" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:   { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:  { src: "10.0.0.10", dst: "10.0.0.20" }
      - vxlan: { vni: 16777216 }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:   { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:  { src: "10.0.0.10", dst: "10.0.0.20" }
      - vxlan: { vni: 100 }
      - eth:   { src: "00:22:33:44:55:66", dst: "00:33:44:55:66:77" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:   { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:  { src: "10.0.0.10", dst: "10.0.0.20" }
      - udp:   { sport: 49152, dport: 4789 }
      - vxlan: { vni: 100 }
```

```yaml-bad
link_type: ethernet
flows:
  - name: vx
    stack:
      - eth:   { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:  { src: "10.0.0.10", dst: "10.0.0.20" }
      - udp:   { sport: 49152, dport: 4789 }
      - vxlan: { vni: 100 }
      - tcp_session: { open: handshake, close: none }
    messages:
      - from: src
        stack:
          - payload_hex: 0xab
```

## 相关

`pmaker://schema/udp`、`pmaker://schema/eth`、`pmaker://schema/ipv4`、`pmaker://schema/gre`、
`pmaker://examples/tunnel/vxlan_ipv4.yaml`、`pmaker://examples/tunnel/vxlan_vlan.yaml`
