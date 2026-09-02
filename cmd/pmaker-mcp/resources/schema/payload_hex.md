# payload_hex —— 原始字节兜底(标量层)

当 gopacket 无法表达某种协议或畸形时,直接落原始字节。`payload_hex` 是**标量层**:
层值直接是十六进制串,不是 map,无需包裹字段。

```yaml
- payload_hex: "0xdeadbeef"
```

对照:`payload` 层是 map 形式(`- payload: { payload: "..." }`),见 `pmaker://schema/payload`。
两者产出的都是原始字节,区别只在写法与编码 —— 文本内容用 `payload`,精确字节用 `payload_hex`。

| 写法 | 形态 | 适用 |
|------|------|------|
| `- payload_hex: "0xdeadbeef"` | 标量 | 精确控制每个字节;不可读文本 |
| `- payload: { payload_hex: "0xdeadbeef" }` | map 内字段 | 等价,与 `payload` 字段同层可读性稍好 |

## 约定

- 接受 `0x` 前缀十六进制串;长度须为偶数个十六进制字符。
- **不可用 `@file(...)`**:`payload_hex` 是 hex 编码字段,注入原始字节会破坏 hex 语义。
  二进制文件内容请用 `payload` + `@file(...)`。
- 兜底层不参与 next-proto 串接,也无 checksum/length 自动计算 —— 字节原样上 wire。
