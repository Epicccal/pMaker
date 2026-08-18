# smtp_request —— SMTP 信封命令(L7,走 tcp)

一条信封命令 = 一个 `smtp_request` 层。MAIL/RCPT 走结构化信封路径(`from`/`to` + `params`),
其余 verb 用 `args` 携带普通参数。verb 原样输出(不强制大写)。

```yaml
- smtp_request:
    verb: EHLO
    args: mail.example.com
- smtp_request:
    verb: MAIL
    from: sender@example.com
    params:
      SIZE: 1000
      SMTPUTF8: ""        # 空值=裸 flag
- smtp_request:
    verb: RCPT
    to: rcpt@example.com
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `verb` | string | 是 | EHLO/HELO/MAIL/RCPT/DATA/QUIT/RSET/NOOP/VRFY/EXPN/HELP/AUTH/STARTTLS/BDAT/ETRN/ATRN;非标走 `payload`/`payload_hex` |
| `from` | string(指针) | MAIL 必填 | 反向路径;省略(nil)报错;`""`→`<>`(退信);`"addr"`→`<addr>` |
| `to` | string | RCPT 必填 | 前向路径,须非空 |
| `params` | map[string]string | 仅 MAIL/RCPT | 扩展参数,保留 YAML 声明顺序输出、支持重复键(如多个 `ORCPT`);空值=裸键(如 `SMTPUTF8`),非空=`KEY=VALUE` |
| `args` | string | 非 MAIL/RCPT verb | 普通参数(如 EHLO 域名、AUTH 机制+凭证);MAIL/RCPT 禁用 |

## verb 参数要求

- 必带 args:EHLO/HELO/VRFY/EXPN/AUTH/BDAT/ETRN/SEND/SOML/SAML
- 禁带 args:DATA/RSET/QUIT/STARTTLS/TURN
- 可选:NOOP/HELP/ATRN
- `params` 仅 MAIL/RCPT 有效,给其他 verb 报错

> DATA 正文用 `eml_data` 层结构化构造（headers + body，SMTP 接入层自动 dot-stuffing 与终止符）；也可用 `payload`/`payload_hex` 兜底（自行 dot-stuff + 终止符）。
