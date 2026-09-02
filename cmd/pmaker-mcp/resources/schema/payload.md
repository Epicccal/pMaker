# payload —— 原始字节兜底(map 层)

当结构化层表达不了某种协议或畸形时,直接落原始字节。本层是 **map 形式**;
标量写法 `- payload_hex: "0x..."` 见 `pmaker://schema/payload_hex`。
通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
packets:
  - stack:
      - eth:     { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4:    { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - tcp:     { sport: 40000, dport: 80, flags: [PSH, ACK], seq: 1000 }
      - payload: { payload: "GET / HTTP/1.1\r\n\r\n" }
```

## 字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `payload` | string | 文本 / 字节内容;支持 `@file(path)` 注入文件原始字节(含二进制),可拼接 |
| `payload_hex` | string | `0x…` 十六进制字节;与 `payload` **互斥** |

`@file` 用法(路径相对 workdir / scenario 目录;可只占字段值的一部分,可多个拼接):

```text
- payload: { payload: "prefix|@file(assets/blob.bin)|suffix" }
```

## 组合规则

- `payload` 与 `payload_hex` 二选一,同时写会被拒。
- 可作为 **flow message 的 payload 生产层**(白名单内),也可用在 standalone `packets`。
- 同一个 stack / message 里可以有**多个** payload 生产层,按声明顺序拼接字节。
- 兜底层**不参与 next-proto 串接**:上一层的自动推导会落到 default(`eth` → `0x0800`、
  `ipv4` → TCP/6),需要别的值就显式写上一层的 `ethertype` / `protocol`。

## 静默陷阱

- **`payload` 字段里的 `\r\n` 是否转义取决于 YAML 引号**。双引号 `"a\r\nb"` 会被 YAML 解析成
  真正的 CR LF;单引号 `'a\r\nb'` 是字面反斜杠 + r。手写协议文本时务必用双引号。
- **不做任何 CRLF 归一化**:`|` 块标量带进来的裸 `\n` 会原样上 wire。要 CRLF 就自己写全。
- **不做长度检查**:巨大的 `@file` 会撑爆 IP 长度字段并静默回绕。走 flow 时用
  `message.segment.mss` 切段;走 `packets` 时自己控制大小。
- `@file` 引用的文件必须随场景归档,否则换机器不可复现(工具的确定性承诺只覆盖同样的输入字节)。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 结构化层不支持的协议 / 字段 | 整段手拼 `payload` 或 `payload_hex` |
| 精确到字节的畸形头 | `payload_hex`(标量层写法更简洁) |
| 二进制附件 / 大文件内容 | `payload` + `@file(...)`(**不能**用 `payload_hex` + `@file`) |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `payload 和 payload_hex 只能配置一个` | 二选一。文本用 `payload`,精确字节用 `payload_hex`;要拼接就都写进同一个字段 |
| `payload_hex 需要 0x 前缀` | 十六进制串必须以 `0x` 开头,如 `0xdeadbeef` |
| `payload_hex 需要偶数个十六进制字符` | 一个字节两位;补齐高位 0(`0x0a` 而非 `0xa`) |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4:    { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:     { sport: 1, dport: 2 }
      - payload: { payload: "hi", payload_hex: "0xdead" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4:    { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:     { sport: 1, dport: 2 }
      - payload: { payload_hex: "deadbeef" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - ipv4:    { src: "10.0.0.1", dst: "10.0.0.2" }
      - udp:     { sport: 1, dport: 2 }
      - payload: { payload_hex: "0xdea" }
```

## 相关

`pmaker://schema/payload_hex`、`pmaker://schema/_conventions`(`@file` 与兜底通则)
