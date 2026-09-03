# payload_hex —— 原始字节兜底(标量层)

与 `payload` 层同源,区别只在写法:**层值直接是十六进制串,不是 map**。
适合精确到字节的构造。通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - udp:  { sport: 40000, dport: 4789 }
      - payload_hex: "0xdeadbeef"
```

## 字段

无字段。层值即内容,须是 `0x` 前缀、偶数位的十六进制串(允许空格分组,如 `"0xde ad be ef"`)。

三种等价写法:

| 写法 | 形态 | 适用 |
|------|------|------|
| `- payload_hex: "0xdeadbeef"` | 标量层 | 精确字节,最简洁 |
| `- payload: { payload_hex: "0xdeadbeef" }` | map 内字段 | 与其它 payload 字段并列时 |
| `- payload: { payload: "..." }` | map 内字段 | 可读文本 / `@file` 二进制注入 |

## 组合规则

- 可作为 flow message 的 payload 生产层,也可用在 standalone `packets`。
- 同一 stack 里可写多个,按顺序拼接。
- 兜底层不参与 next-proto 串接,也无 checksum / length 自动计算 —— 字节原样上 wire。

## 静默陷阱

- **不可用 `@file(...)`**:本字段是 hex 编码,注入原始字节会破坏 hex 语义(而且多半直接报
  "非法十六进制字符")。二进制文件内容用 `payload` + `@file`。
- **YAML 会把不带引号的 `0xdeadbeef` 解析成整数**,进而变成十进制数字串。始终加引号。
- 它不是"整包替换":`payload_hex` 只是栈里的一层,外面的 `eth` / `ipv4` 照常自动计算长度与
  校验和。要连 IP 头都手拼,就把 `payload_hex` 放在栈首(并把 `link_type` 设对)。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 结构化层不支持的协议头(GRE Key、TCP option、IP 分片、VLAN PCP…) | 从该层起整段 `payload_hex` |
| 截断的 / 多余字节的报文尾 | 在正常栈末尾追加一层 `payload_hex` |
| 完全自定义的链路层帧 | 栈首 `payload_hex` + 对应的 `link_type` |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `payload_hex 需要 0x 前缀` | 必须 `0x` 开头,如 `"0xdeadbeef"`;别写纯 hex 或 `\x` 转义 |
| `payload_hex 需要偶数个十六进制字符` | 一个字节两位,补齐高位 0 |
| `payload_hex 不能为空` | `"0x"` 不合法。要"零字节负载"就干脆不写这一层 |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 1, dport: 2 }
      - payload_hex: "deadbeef"
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 1, dport: 2 }
      - payload_hex: "0xdea"
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:  { sport: 1, dport: 2 }
      - payload_hex: "0x"
```

## 相关

`pmaker://schema/payload`、`pmaker://schema/_conventions`
