# ftp_response —— FTP 控制连接响应(L7,走 tcp)

```yaml
- ftp_response:
    code: 220
    message: "FTP server ready"
```

多行续行(RFC 959 §4.1.3):

```yaml
- ftp_response:
    code: 227
    lines:
      - "Entering Passive Mode"
      - "h1,h2,h3,h4,p1,p2"
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `code` | int | 是 | 三位 100-599(首位 1-5);越界报错并引导 `payload`/`payload_hex` |
| `message` | string | 与 `lines` 二选一 | 单行:`code message\r\n` |
| `lines` | []string | 与 `message` 二选一 | 多行续行:每行带 `code-` 前缀,末行 `code[ SP text]` |

> `message` 与 `lines` 互斥,必须有一个。
