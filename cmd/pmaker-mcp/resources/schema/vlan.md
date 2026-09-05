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
| `vid` | uint16 | 否(缺省 0) | VLAN ID(12 位,`0..4095`;>4095 校验报错) |
| `type` | `Hex` | 否 | 显式覆盖本层标签后的 TPID/EtherType(制造断链),缺省自动推导 |

`Dot1Q.Type` 的取值:显式 `type` 优先;缺省自动推导(后接 `vlan` → `0x8100`、
`ipv4` → `0x0800`、`ipv6` → `0x86dd`;其余非 IP 结构化层(如 `gre`)报错。
兜底例外:后接 `payload` / `payload_hex` 或无下一层时落 `0x0800`)。

## 组合规则

- 无必填字段:`- vlan: {}` 合法(VID=0,priority tag)。
- 层数不设上限,多层按声明顺序由外到内。
- `vid` 是 12 位字段,合法值 `0..4095`;4095 按字段表达能力放行(保留值,可用于畸形用例)。
- `type` 超 16 位(如 `0x12345`)报错,不静默截断。
- 外层 S-TAG 的 TPID **写在 `eth.ethertype` 上**(`0x88a8`),vlan 层管不到。
- 双层标签间非标 TPID:上一层 vlan 写 `type: 0x88a8`(见下方 QinQ 写法)。

QinQ 完整写法:

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb", ethertype: 0x88a8 }
      - vlan: { vid: 100 }                 # 外层 S-TAG,下一层是 vlan → type 自动 0x8100
      - vlan: { vid: 200 }                 # 内层 C-TAG,type 自动推导为 ipv4 的 0x0800
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 40000, dport: 80, flags: [SYN] }
```

## 静默陷阱

- **`vid` 不写就是 0,不会提示。** VID 0 是合法的 priority tag,但多半不是你想要的。
- 802.1p 优先级(PCP)与 DEI 位当前**不开放**,恒为 0;需要非零 PCP 只能整段走 `payload_hex`。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 解析断链(标签后声明的下一层与实际不符) | `type: 0xffff` |
| 非标 S-TAG TPID(设备认不认 `0x8100` 做双层) | `eth.ethertype: 0x8100` + 两层 vlan |
| 非标标签间 TPID(如 `0x88a8`/`0x9100`) | 上一层 vlan 的 `type: 0x88a8` |
| 超深标签栈 | 连写多层 `- vlan: {...}` |
| 非法 VID(>4095) | 整段走 `payload_hex`(校验阶段报 `超出 12 位`) |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `层 "vlan" 不支持字段` | vlan 只有 `vid` / `type` 两个字段;`tpid`、`priority`、`dei`、`pcp` 均不存在(非标 TPID 走 `type`/`ethertype`),其余走 `payload_hex` |
| `vlan.vid 超出 12 位` | VID 上限 4095;需要"非法 VID"用例时写 `vid: 4095`(保留值)或整段走 `payload_hex` |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - vlan: { vid: 100, priority: 5 }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
```

vid 超 12 位被校验拦截:

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - vlan: { vid: 4096 }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
```

type 超 16 位被校验拦截(不静默截断):

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - vlan: { vid: 100, type: 0x12345 }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
```

## 相关

`pmaker://schema/eth`、`pmaker://schema/gre`、`pmaker://examples/tunnel/qinq_gre.yaml`
