# vlan —— 802.1Q / QinQ 标签(L2)

夹在 `eth` 与网络层之间,**可重复**(QinQ 双层甚至多层)。后接 `vlan`(继续套标签)或网络层。
`flow.stack` 同样支持(夹在 `eth` 与网络层之间,标签链重建到每个展开包;QinQ 多层照写),
并可用 `src_vid`/`dst_vid` 让上下行带不同标签(见「组合规则」)。
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
| `src_vid` | uint16 | 否 | **仅 `flow.stack`**:上行(src→dst)方向的 VID,与 `vid` 互斥;缺省 = 上行摘除该层 |
| `dst_vid` | uint16 | 否 | **仅 `flow.stack`**:下行(dst→src)方向的 VID,与 `vid` 互斥;缺省 = 下行摘除该层 |
| `pri` | uint8 | 否(缺省 0) | PCP 优先级(802.1p,TCI 高 3 位,`0..7`;>7 校验报错) |
| `dei` | bool | 否(缺省 false) | Drop Eligible Indicator(TCI 第 4 位) |
| `type` | `Hex` | 否 | 显式覆盖本层标签后的 TPID/EtherType(制造断链),缺省自动推导 |

`Dot1Q.Type` 的取值:显式 `type` 优先;缺省自动推导(后接 `vlan` → `0x8100`、
`ipv4` → `0x0800`、`ipv6` → `0x86dd`;其余非 IP 结构化层(如 `gre`)报错。
兜底例外:后接 `payload` / `payload_hex` 或无下一层时落 `0x0800`)。

## 组合规则

- 无必填字段:`- vlan: {}` 合法(VID=0,priority tag)。
- 层数不设上限,多层按声明顺序由外到内。
- `vid` 是 12 位字段,合法值 `0..4095`;4095 按字段表达能力放行(保留值,可用于畸形用例)。
- `pri`(PCP)合法值 `0..7`;`dei` 写入 TCI 对应位。`pri`/`dei` 与 `vid` 共同组成 TCI,
  需要构造"TCI 整体畸形"(如非标位组合)时,`pri`+`dei`+`vid` 已覆盖 16 位 TCI 的全部语义位,
  仍不够走 `payload_hex`。
- `type` 超 16 位(如 `0x12345`)报错,不静默截断。
- 外层 S-TAG 的 TPID **写在 `eth.ethertype` 上**(`0x88a8`),vlan 层管不到。
- 双层标签间非标 TPID:上一层 vlan 写 `type: 0x88a8`(见下方 QinQ 写法)。
- **flow 封装**:`flow.stack` 里 vlan 夹在 `eth` 与网络层之间(不可在最外层、不可在网络层之后),
  标签链会重建到该 flow 的每个展开包(握手/数据/挥手),vid/type 全部保留。
- **方向化 VID(仅 `flow.stack`)**:`src_vid`(上行 src→dst,即 TCP SYN 发起方发出的包)/
  `dst_vid`(下行 dst→src)取代 `vid`,展开器按每个包自身的方向取值,与 `vid` **互斥**
  (混写无唯一解释,硬错;`vid: 0` 与"未写"不可区分,不算冲突)。
  **单边缺省 = 该方向整层摘除**(不是"VID 取 0"):此方向的包里没有这一层标签。
- 方向 VID 写法 → 展开效果:`{ vid: 100 }` 两向都是 100(经典写法,不必用方向字段);
  `{ src_vid: 300, dst_vid: 400 }` 上行 300 / 下行 400;`{ src_vid: 100 }` 下行摘除该层;
  外层 `{ src_vid: 100, dst_vid: 500 }` + 内层 `{ src_vid: 200 }` = 上行双层、下行单层。
- 方向 VID 只在 `flow.stack` 有效:standalone `packets` / `message.stack` 无方向语义,写了直接报错
  (逐包写 stack 本就能表达任意方向差异,不做"当 `vid` 用"的静默降级)。
- `pri` / `dei` / `type` 与方向 VID 共存时**两向共用**(v1 不做方向化 PCP/DEI/TPID);
  需要两向不同的 PCP/TPID 时改用 standalone `packets` 逐包写。每层独立声明方向
  (多层 vlan 可一层两向、另一层单向)。

方向化 VID 写法(上行双层 100→200、下行单层 500):

```yaml
link_type: ethernet
flows:
  - name: dir-qinq-mix
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - vlan: { src_vid: 100, dst_vid: 500 }   # 外层:上行 100 / 下行 500
      - vlan: { src_vid: 200 }                 # 内层:仅上行有,下行摘除
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - payload: { payload: "up" }
      - from: dst
        stack:
          - payload: { payload: "down" }
```

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
- `pri` 不写就是 0。写 `pri: 0` + `vid: 0` 虽是字段语义上的 priority tag,与不写无 wire 差异。
- **方向 VID 摘层时,写死的 `eth.ethertype` 不会跟着变。** 下行摘光标签后仍声明 `0x8100`
  就是解析断链;想让两向各自正确,别写 `eth.ethertype`,交由逐包自动推导。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 解析断链(标签后声明的下一层与实际不符) | `type: 0xffff` |
| 非标 S-TAG TPID(设备认不认 `0x8100` 做双层) | `eth.ethertype: 0x8100` + 两层 vlan |
| 非标标签间 TPID(如 `0x88a8`/`0x9100`) | 上一层 vlan 的 `type: 0x88a8` |
| 超深标签栈 | 连写多层 `- vlan: {...}` |
| 非零 PCP(QoS/优先级队列验证) | `pri: 5` 等,`0..7` |
| DEI 置位(丢弃策略验证) | `dei: true` |
| 非法 VID(>4095) | 整段走 `payload_hex`(校验阶段报 `超出 12 位`) |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `层 "vlan" 不支持字段` | vlan 只有 `vid` / `src_vid` / `dst_vid` / `pri` / `dei` / `type` 六个字段;`tpid`、`priority`、`pcp` 均不存在(优先级用 `pri`,非标 TPID 走 `type`/`ethertype`),其余走 `payload_hex` |
| `vlan.vid 超出 12 位` | VID 上限 4095;需要"非法 VID"用例时写 `vid: 4095`(保留值)或整段走 `payload_hex` |
| `vlan.pri 超出 3 位` | PCP 上限 7;整段走 `payload_hex` 无法表达"PCP>7"(TCI 位放不下),该畸形本身不存在 |
| `vlan.vid 与 vlan.src_vid/dst_vid 互斥` | 一层里二选一:两向同 VID 只写 `vid`,两向不同只写 `src_vid`/`dst_vid` |
| `只在 flow.stack 内有效` | `src_vid`/`dst_vid` 只能写在 `flow.stack` 的 vlan 上;standalone `packets` 改用 `vid`,方向差异逐包写 stack |
| `vlan.src_vid: vlan.vid 超出 12 位` | 方向 VID 同样是 12 位,上限 4095(`dst_vid` 同理) |
| `stack.vlan: 层序须为` | 仅 `flow.stack`:vlan 须在 `eth` 之后、网络层之前(展开器按声明序成帧;standalone `packets` 无此约束)。vlan 写在 eth 前 / 网络层后都报此错 |

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

pri 超 3 位(PCP 值域 0-7)被校验拦截:

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - vlan: { vid: 100, pri: 8 }
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

flow.stack 的 vlan 写在 eth 之前被校验拦截(vlan 须夹在 eth 与网络层之间,写成最外层也报同一错):

```yaml-bad
link_type: ethernet
flows:
  - name: vlan-misplaced
    stack:
      - tcp:  { sport: 49152, dport: 80 }
      - vlan: { vid: 100 }
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - payload: { payload: "x" }
```

flow.stack 的 vlan 写在网络层之后被校验拦截(标签须紧贴以太头,内层无法成帧):

```yaml-bad
link_type: ethernet
flows:
  - name: vlan-too-deep
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - vlan: { vid: 100 }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - payload: { payload: "x" }
```

方向 VID 与 `vid` 混写被校验拦截(哪个方向落哪个值无唯一解释):

```yaml-bad
link_type: ethernet
flows:
  - name: vlan-vid-conflict
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - vlan: { vid: 100, src_vid: 300 }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - payload: { payload: "x" }
```

standalone `packets` 里写方向 VID 被校验拦截(无 src/dst 方向语义):

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - vlan: { src_vid: 300, dst_vid: 400 }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
```

方向 VID 超 12 位被校验拦截(与 `vid` 同一值域):

```yaml-bad
link_type: ethernet
flows:
  - name: vlan-src-vid-over
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - vlan: { src_vid: 4096 }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - payload: { payload: "x" }
```

## 相关

`pmaker://schema/eth`、`pmaker://schema/gre`、`pmaker://examples/tunnel/qinq_gre.yaml`、
`pmaker://examples/tunnel/vlan_flow.yaml`、`pmaker://examples/tunnel/vlan_directional.yaml`
