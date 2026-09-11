# gre —— GRE 隧道封装(L3)

隧道层:外层 IP 之后再套一整个内层报文,**可递归**。当前**无任何字段**(`- gre: {}`),
next-proto 全自动推导。通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "1.1.1.1", dst: "2.2.2.2" }              # 外层,protocol 自动 = 47
      - gre:  {}                                               # protocol 自动 = 内层 EtherType
      - ipv4: { src: "192.168.1.1", dst: "192.168.1.2" }       # 内层 IP
      - tcp:  { sport: 1234, dport: 443, flags: [SYN] }
```

## 字段

无。`- gre: {}` 是唯一合法写法。写任何键都会被拒(见「报错 → 改法」)。

`GRE.Protocol` = **内层 EtherType**,按内层第一层推导:内层 `ipv4` → `0x0800`、
内层 `ipv6` → `0x86dd`、内层 `vlan` → `0x8100`;内层为其他层(含 `eth`)报错
(**注意:TEB `0x6558` 不在推导表内**,见「静默陷阱」)。外层 IP 的 protocol 自动 = 47。

## 组合规则

- 内层可以是任意完整栈,包括再来一层 `gre`(多重隧道)。
- 内层 TCP/UDP 的校验和伪首部绑定**内层 IP**(builder 记录最近一个网络层),不是外层。
- `flow.stack` 不支持 GRE。flow 目前支持普通单段栈与一层 VXLAN 两段栈;GRE 隧道内嵌
  会话只能用 `packets` 逐包写。

## 静默陷阱

- **TEB(内层是 `eth`,Transparent Ethernet Bridging)不可构造**。RFC 1701 规定
  TEB 为 `0x6558`,但本工具的 EtherType 推导表里没有 `eth` 这一项,构建时报错。
  构造 GRE-over-Ethernet 时须整段 `payload_hex` 手拼。
- GRE 头的可选位(Checksum Present / Key Present / Sequence Number Present)与对应字段
  **全部不开放**,恒为 0 —— 也就是说只能生成 4 字节的最简 GRE 头。带 Key 的 GRE(常见于
  运营商隧道)当前无法结构化构造。
- 隧道叠加会增加头部开销,但工具**不做 MTU 检查**:内外层长度自动计算各自独立,超 MTU 的巨包
  会被照常写进 pcap。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 外层 protocol 与实际不符(断链) | 外层 `ipv4: { protocol: udp }` |
| GRE protocol 与内层不符 | 无字段可覆盖,整段 `payload_hex` 手拼 GRE 头 |
| 带 Key / Checksum 位的 GRE 头 | 无字段,整段 `payload_hex` |
| 内层报文本身畸形 | 正常写内层各层的 `checksum` / `total_length` 覆盖 |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `层 "gre" 不支持字段` | GRE 当前无任何字段,只能写 `- gre: {}`。要 Key / Sequence / Checksum 位,整段走 `payload_hex` |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "1.1.1.1", dst: "2.2.2.2" }
      - gre:  { key: 0x1234 }
      - ipv4: { src: "192.168.1.1", dst: "192.168.1.2" }
      - tcp:  { sport: 1, dport: 2 }
```

## 相关

`pmaker://schema/ipv4`、`pmaker://schema/vlan`、`pmaker://schema/payload_hex`、
`pmaker://examples/tunnel/qinq_gre.yaml`
