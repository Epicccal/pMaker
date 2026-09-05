# vlan —— 802.1Q / QinQ 标签(L2)

夹在 `eth` 与网络层之间,**可重复**(QinQ 双层甚至多层)。后接 `vlan`(继续套标签)或网络层。
通则(两态覆盖 / 兜底 / `@file`)见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - vlan: { vid: 100 }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - tcp:  { sport: 40000, dport: 80, flags: [SYN], seq: 1000 }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `vid` | uint16 | 否(缺省 0) | VLAN ID |
| `tpid` | `Hex` | 否 | **下一个标签**的 TPID;**仅当下一层还是 `vlan` 时生效**,见「静默陷阱」 |
| `type` | `Hex` | 否 | 显式覆盖 next-proto(制造断链),优先级高于 `tpid` 与自动推导 |

`Dot1Q.Type` 的取值按优先级:显式 `type` > `tpid`(仅 next 为 `vlan`)> 自动推导
(后接 `vlan` → `0x8100`、`ipv4` → `0x0800`、`ipv6` → `0x86dd`;其余非 IP 结构化层
(如 `gre`)报错。兜底例外:后接 `payload` / `payload_hex` 或无下一层时落 `0x0800`)。

## 组合规则

- 无必填字段:`- vlan: {}` 合法(VID=0,priority tag)。
- 层数不设上限,多层按声明顺序由外到内。
- 外层 S-TAG 的 TPID **写在 `eth.ethertype` 上**(`0x88a8`),不是写在第一层 vlan 的 `tpid` 上。

QinQ 完整写法:

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb", ethertype: 0x88a8 }
      - vlan: { vid: 100, tpid: 0x8100 }   # 外层 S-TAG,下一层仍是 vlan → tpid 生效
      - vlan: { vid: 200 }                 # 内层 C-TAG,next 自动推导为 ipv4
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 40000, dport: 80, flags: [SYN] }
```

## 静默陷阱

- **`tpid` 在最内层 vlan 上会被静默丢弃**。`- vlan: { vid: 100, tpid: 0x88a8 }` 后面接 `ipv4` 时,
  wire 上是 `8100 0064`(自动推导),`0x88a8` 不生效、不报错、不告警 —— 因为 `tpid` 描述的是
  *下一个标签*的 TPID。要让**本层**标签的 TPID 非标,得改上一层:第一层改 `eth.ethertype`,
  中间层改上一层 vlan 的 `type`。
- `vid` 不写就是 0,不会提示。VID 0 是合法的 priority tag,但多半不是你想要的。
- 802.1p 优先级(PCP)与 DEI 位当前**不开放**,恒为 0;需要非零 PCP 只能整段走 `payload_hex`。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 解析断链(标签后声明的下一层与实际不符) | `type: 0xffff` |
| 非标 S-TAG TPID(设备认不认 `0x8100` 做双层) | `eth.ethertype: 0x8100` + 两层 vlan |
| 超深标签栈 | 连写多层 `- vlan: {...}` |
| 非法 VID(>4094)/ 带 PCP 的标签 | 整段走 `payload_hex` |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `层 "vlan" 不支持字段` | vlan 只有 `vid` / `tpid` / `type` 三个字段;`priority`、`dei`、`pcp` 均未实现,走 `payload_hex` |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - vlan: { vid: 100, priority: 5 }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
```

## 相关

`pmaker://schema/eth`、`pmaker://schema/gre`、`pmaker://examples/tunnel/qinq_gre.yaml`
