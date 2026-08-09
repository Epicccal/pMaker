# ftp_request —— FTP 控制连接命令(L7,走 tcp)

一条命令 = 一个 `ftp_request` 层,序列化为 TCP payload。

```yaml
- ftp_request:
    command: USER
    args: anonymous
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `command` | string | 是 | RFC 959 核心 + 常见扩展(大小写不敏感);未列入报错并引导用 `payload`/`payload_hex` |
| `args` | string | 否 | 命令参数(如 `USER` 的用户名、`RETR` 的路径) |

> `command` 原样输出(不强制大写),可构造小写/非标命令等畸形用例。非标命令走 `payload`/`payload_hex` 原始字节兜底。
