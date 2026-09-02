# payload / payload_hex —— 原始字节兜底

当 gopacket 无法表达某种协议或畸形时,直接落原始字节。

## payload(文本/二进制字节)

```yaml
- payload:
    payload: "GET / HTTP/1.1\r\n\r\n"
```

也支持 `@file(...)` 注入文件原始字节(含二进制):

```yaml
- payload:
    payload: "@file(assets/eml/message.eml)"
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `payload` | string | 文本/字节内容,可与 `@file` 拼接;与 `payload_hex` 互斥 |
| `payload_hex` | `Hex` | `0x...` 十六进制字节;与 `payload` 互斥 |

## payload_hex(标量,非 map)

直接作为层值,无需包裹:

```yaml
- payload_hex: "0xdeadbeef"
```

详见 `pmaker://schema/payload_hex`。

> `payload_hex` 是 hex 编码字段,`@file` 注入原始字节会破坏 hex 语义;二进制内容请用 `payload`。
