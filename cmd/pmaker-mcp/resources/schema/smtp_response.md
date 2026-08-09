# smtp_response —— SMTP 响应(L7,走 tcp)

单行/多行遵循 RFC 5321 §4.2 的 Reply-line 文法(每条续行带 `code-` 前缀,末行 `code[ SP text]`)。

```yaml
- smtp_response:
    code: 220
    message: "mail.example.com ESMTP ready"
```

多行:

```yaml
- smtp_response:
    code: 250
    lines:
      - "mail.example.com"
      - "AUTH PLAIN LOGIN"
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `code` | int | 是 | 200-559(SMTP 无 1xx,首位 2-5);非标走 `payload`/`payload_hex` |
| `message` | string | 与 `lines` 二选一 | 单行:`code message\r\n` |
| `lines` | []string | 与 `message` 二选一 | 多行续行:每行带 `code-` 前缀,末行 `code[ SP text]`;空文本行如实输出(合规) |

> `message` 与 `lines` 互斥,必须有一个。
