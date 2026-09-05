# eth —— 以太网层(L2)

栈的最外层(`link_type: ethernet` 时)。后接 `vlan` / `ipv4` / `ipv6`。
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
| `src` | MAC 字符串 | 是 | 源 MAC,`aa:bb:cc:dd:ee:ff` 形式 |
| `dst` | MAC 字符串 | 是 | 目的 MAC |
| `ethertype` | `Hex` | 否 | 覆盖自动推导的 EtherType;QinQ 外层 S-TAG 常用 `0x88a8` |

EtherType 自动推导:后接 `vlan` → `0x8100`、`ipv4` → `0x0800`、`ipv6` → `0x86dd`;
其余**非 IP 结构化层**(`gre`/`tcp`/`udp`/… 等)报错。兜底例外:后接 `payload` /
`payload_hex` 或无下一层时仍落 `0x0800`(raw 尾巴无目标层可推,这是惯例缺省)。

## 组合规则(硬错)

- `src` / `dst` 缺一不可。
- `flow.stack` **必须**含 `eth`;standalone `packets` 无此要求(见「静默陷阱」)。
- MAC 字符串的**格式**在出包阶段才解析:`generate_yaml` 会放行 `src: "zz"`,`generate_pcap` 才报错。
- `ethertype` 超 16 位(如 `0x12345`)报错,不静默截断。

## 静默陷阱

- **`link_type` 与栈首层不匹配不会被拦**。`packets` 不强制写 `eth`,而 `link_type` 缺省是
  `ethernet` —— 一个 `ipv4` 打头的 stack 会被写进声明为 Ethernet 的 pcap,解析端把 IP 头当 MAC 读,
  不报错不告警。**只有 L3 报文时须显式写 `link_type: raw`**(或 `ipv4` / `ipv6`)。
- **写了 `ethertype` 就是断链**:值与实际下一层不符不会有任何提示。这正是构造用途,但误写同样无声。
- 后接 `payload` / `payload_hex` / 无下一层时落 `0x0800` 而非其真实 EtherType
  (raw 尾巴无目标层可推),需要别的值必须显式写 `ethertype`;其余推导表之外的
  结构化下一层直接报错。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 解析断链(EtherType 与实际下一层不符) | `ethertype: 0xffff` |
| 非标 QinQ S-TAG TPID(设备认不认 `0x8100` 做双层) | `ethertype: 0x8100` + 两层 `vlan`,见 `pmaker://schema/vlan` |
| 截断 / 非法的 MAC 头本身 | 整包走 `payload_hex`(兜底层不参与串接) |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `stack 需要 eth 层` | 这是 `flow.stack` 的硬约束(还须含 `tcp`、恰好一个网络层、`tcp_session`;可选夹多层 `vlan`,见 `pmaker://schema/vlan`)。要构造无以太头的 L3 会话,改用 `packets` 逐包写并设 `link_type: raw` |

```yaml-bad
link_type: ethernet
flows:
  - name: no-eth
    stack:
      - ipv4:        { src: "10.0.0.10", dst: "10.0.0.80" }
      - tcp:         { sport: 49152, dport: 80 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - payload: { payload: "hi" }
```

## 相关

`pmaker://schema/vlan`、`pmaker://schema/gre`、`pmaker://examples/tunnel/qinq_gre.yaml`
