# vxlan —— VXLAN 隧道封装(UDP 承载二层隧道,RFC 7348)

隧道层:`udp`(标准端口 4789)之后再套一个 inner Ethernet 帧。VXLAN 头固定 8 字节。
当前仅 standalone `packets` 支持,**`flow.stack` 不支持**。通则见 `pmaker://schema/_conventions`。

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
- inner `eth` 之后的内容不做进一步校验(`vxlan → eth → eth` 双层 eth 可构造,是字段错位的
  规避流量形态)。
- **`flow.stack` 不支持 `vxlan`**:flow 展开器无隧道方向反转与内层会话处理能力。
  VXLAN 内的 TCP 会话只能用 `packets` 逐包写。

## 静默陷阱

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
| `vxlan 不支持在 flow.stack 中使用` | VXLAN 会话用 `packets` 逐包写;flow 展开器不支持隧道 |

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
