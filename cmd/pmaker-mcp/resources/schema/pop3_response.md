# pop3_response —— POP3 服务器响应(L7,走 tcp)

单行 `+OK`/`-ERR [text]\r\n`,或多行(`status` 行 + 正文 + `<CRLF>.<CRLF>` 终止符);
SASL 续行挑战为 `+ [base64]\r\n`(RFC 1734/4954,单字符 `+` 而非 `+OK`)。
`status` 原样输出(不强制大写),保留 `+ok`/`-err` 等大小写构造能力;非标状态指示符走
`payload`/`payload_hex`。

单行(`message`):

```yaml
- pop3_response:
    status: "+OK"
    message: "POP3 server ready"
```

多行普通行列表(`lines`,如 LIST/UIDL 扫描列表、CAPA 能力列表):

```yaml
- pop3_response:
    status: "+OK"
    lines:
      - "1 1200"
      - "2 840"
      - "3 512"
```

多行 RFC 5322 邮件正文(`eml`,RETR/TOP,复用 `eml_data` 子结构):

```yaml
- pop3_response:
    status: "+OK"
    eml:
      headers:
        From: alice@example.com
        Subject: Hello
      body: "Hi there.\r\n"
```

多行响应首行带说明文本(`message` + `lines`/`eml`,RFC 1939 §3 合法形态):
LIST 的 `+OK 2 messages (320 octets)`、CAPA 的 `+OK Capability list follows`、
RETR 的 `+OK message 1 follows` 等都是首行带文本的多行响应。

```yaml
- pop3_response:
    status: "+OK"
    message: "2 messages (320 octets)"
    lines:
      - "1 1200"
      - "2 2000"
```

SASL 续行挑战(`status: "+"`,`message` 承载 base64 挑战,RFC 1734/4954):

```yaml
- pop3_response:
    status: "+"
    message: "AGFsaWNlAHNlY3JldA=="
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `status` | string | 是 | `+OK` / `-ERR` / `+`(大小写不敏感,原样输出);`+` 为 RFC 1734/4954 SASL 续行挑战;非标状态指示符走 `payload`/`payload_hex` |
| `message` | string | 否 | 状态行附带文本:单独非空=单行 `status message\r\n`(SASL 续行则承载 base64 挑战);与 `lines`/`eml` 组合=多行首行带说明文本(RFC 1939 §3);**不能含 `\r` / `\n`**(注入换行符会产出额外响应行,畸形 POP3 字节流请用 `payload`/`payload_hex`) |
| `lines` | []string | 否 | 多行普通行(LIST/UIDL/CAPA…);逐行 dot-stuffing + `<CRLF>.<CRLF>` 终止符;与 `eml` 互斥。**每个元素是一行逻辑内容,不应包含换行符(`\n`/`\r\n`)**——行边界由 builder 在 join 时注入 `\r\n`,元素内嵌换行符不会被识别为行边界,dot-stuffing 也不会在该位置生效。需要构造含嵌入换行的行(畸形场景)请用 `payload`/`payload_hex`。 |
| `eml` | `eml_data` 子结构 | 否 | 多行 RFC 5322 正文(RETR/TOP);字段与 `eml_data` 同构(POP3 会自动做 dot-stuffing 并追加终止符),详见 `pmaker://schema/eml_data`;与 `lines` 互斥 |

> `message` 可与 `lines`/`eml` 任意组合(多行首行带说明文本),也可单独(单行响应);`lines` 与 `eml` 互斥。`message`/`lines`/`eml` 至少其一非空(裸 status 行走 `payload`/`payload_hex`)。**多行正文(`lines`/`eml`)仅 `+OK` 可用** —— RFC 1939 §3 多行响应均 `+OK` 起始(LIST/RETR/TOP/UIDL/CAPA);`-ERR` 永远单行,RFC 1734/4954 SASL 续行 `+` 也是单行挑战,二者搭配 `lines`/`eml` 会被校验拦截(非标多行响应请用 `payload`/`payload_hex`)。多行正文(dot-stuffing + `<CRLF>.<CRLF>`)与 SMTP DATA 同一框架规则;`status` 行不参与 dot-stuff。CAPA 响应用 `lines`(能力标签不区分大小写,如 `SASL CRAM-MD5 KERBEROS_V4`、`STLS`)。SASL 续行挑战用 `status: "+"` + `message: <base64>`(RFC 1734/4954)。**客户端的 SASL 续行响应是一行裸 base64(RFC 1734 §3:"a line containing a BASE64 encoded string",无命令前缀),`pop3_request` 的 `command` 恒输出、无法产生裸 base64 行,须用 `payload`/`payload_hex` 承载**(与私有命令走原始字节兜底同理)。
