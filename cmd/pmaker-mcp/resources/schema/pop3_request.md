# pop3_request —— POP3 客户端命令(L7,走 tcp)

一条 POP3 命令 = 一个 `pop3_request` 层。命令无结构化信封(不像 SMTP MAIL/RCPT),统一走
`command` + `args` 扁平风格(对齐 `ftp_request`)。`command` 原样输出(不强制大写),
保留 `user`/`RETR`/`Retr` 等大小写构造能力(RFC 1939 §3 命令大小写不敏感,是合规测试点)。

```yaml
- pop3_request:
    command: USER
    args: alice
- pop3_request:
    command: RETR
    args: "1"
- pop3_request:
    command: TOP
    args: "1 10"
- pop3_request:
    command: QUIT
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `command` | string | 是 | RFC 1939 核心(USER/PASS/APOP/STAT/LIST/RETR/DELE/NOOP/RSET/TOP/UIDL/QUIT)+ 扩展(CAPA/STLS/AUTH);非标/私有命令走 `payload`/`payload_hex` |
| `args` | string | 视命令 | 命令参数(如 USER 邮箱名、RETR msg#、TOP 的 `msg# n`、APOP 的 `name digest`、AUTH 机制);有/无按下表;**不能含 `\r` / `\n`** |

## command 参数要求

- 必带 args:USER / PASS / APOP / RETR / DELE / TOP / AUTH
- 禁带 args:STAT / NOOP / RSET / QUIT / CAPA / STLS
- 可选 args:LIST / UIDL(无参=多行响应;有参=msg#,单行响应)

> 命令大小写不敏感;非标/私有命令请用 `payload`/`payload_hex`。RETR/TOP 的响应正文用 `pop3_response` 的 `eml` 字段(复用 `eml_data` 子结构,POP3 接入层自动 dot-stuffing + 终止符)。
>
> **SASL 续行响应限制**:`pop3_request` 的 `command` 必填且恒输出,无法产生 SASL 续行所需的裸 base64 行(RFC 1734 §3:AUTH 后续往返是 "a line containing a BASE64 encoded string",无命令前缀)。客户端的 SASL 续行响应须用 `payload`/`payload_hex` 承载裸 base64(参见 `examples/pop3/auth_sasl.yaml`)。
