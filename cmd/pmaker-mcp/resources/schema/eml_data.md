# eml_data —— RFC 5322 邮件内容（协议无关内容层，L7 走 tcp）

一封 RFC 5322 邮件内容(headers + body) = 一个 `eml_data` 层，序列化为 TCP payload 字节。
**协议无关的内容层**：只产 RFC 5322 内容字节，不含成帧。成帧（framing）由承载它的传输
协议自动补上，`eml_data` 自身没有成帧开关：

- **SMTP DATA**（RFC 5321 §4.5.2）/ **POP3 RETR**（RFC 1939 §3）：无论写成独立的
  `eml_data` 层还是 `pop3_response.eml`，都会自动做 dot-stuffing 并追加 `<CRLF>.<CRLF>`
  终止符，无法关闭；缺 dot-stuffing / 缺终止符等畸形走 `payload`/`payload_hex` 原始字节兜底。
- **IMAP**（RFC 9051，FETCH / APPEND）：写成 `imap_request.literal.eml` 或
  `imap_response.literal.eml`，内容字节会被自动加上长度前缀 `{n}\r\n`，
  **不做 dot-stuffing、不加终止符**（IMAP 靠长度定界，不靠点终止符）。

## 结构化模式（规范邮件）

```yaml
- eml_data:
    headers:
      From: "alice@example.com"
      To: "bob@example.net"
      Subject: "Hello"
      Date: "Thu, 01 Jan 2024 00:00:00 +0000"
      Message-ID: "<abc@example.com>"
      MIME-Version: "1.0"
      Content-Type: "text/plain; charset=utf-8"
    body: "This is the email body.\r\nSecond line.\r\n"
```

用作 SMTP DATA 时的序列化结果（headers 按 YAML 声明顺序输出 + 空行 + body，
dot-stuffing 与终止符自动追加）：

```
From: alice@example.com\r\n
To: bob@example.net\r\n
Subject: Hello\r\n
Date: Thu, 01 Jan 2024 00:00:00 +0000\r\n
Message-ID: <abc@example.com>\r\n
MIME-Version: 1.0\r\n
Content-Type: text/plain; charset=utf-8\r\n
\r\n
This is the email body.\r\n
Second line.\r\n
.\r\n
```

## 原始模式（裸透传内容字节，构造畸形内容）

```yaml
- eml_data:
    raw: "From: alice@example.com\r\nTo: b\r\n\r\nbody\r\n"
- eml_data:
    raw: "@file(assets/email.eml)"   # @file 注入外部 EML 文件（只是内容字节，成帧照常自动追加）
    # 注意：.\r\n 是 SMTP/POP3 的传输成帧字节，不是 RFC 5322 内容的一部分。
    # 邮件客户端另存的 .eml、Wireshark「Export Objects → IMF」导出的邮件均不含它，
    # 可直接注入。但 Wireshark「Follow TCP Stream」这类保留完整传输流的导出会含
    # 发送方写入的 .\r\n，此时会再自动追加一次造成双重终止符 —— 应改用
    # payload/payload_hex 精确控制成帧字节。
- eml_data:
    raw_hex: "0x466f6f"              # 二进制内容（hex）
```

raw 模式裸透传内容字节（不拼头体、不归一化），成帧仍会自动追加（dot-stuffing +
终止符）。若要精确控制成帧字节（如自带终止符、缺终止符），直接用 `payload`/`payload_hex`。

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `headers` | map[string]string | 结构化模式必填 | 邮件头（RFC 5322），保留 YAML 声明顺序输出为 `Key: Value\r\n`，支持重复头/有序头（如多个 `Received`）；值含 `\r\n`+空白=folding，`\r\n`+非空白=头注入 |
| `body` | string | 结构化模式可选 | 邮件正文体；可空（合规空体邮件）；支持 `@file(path)` 注入；headers 与 body 间自动插空行；行结束符自动归一化（裸 `\n` → `\r\n`，兼容 YAML `|` 块标量等常用写法；raw 模式不归一化）；与 `multipart` 互斥 |
| `multipart` | object | 结构化模式可选 | MIME multipart body（RFC 2046），作为邮件正文（multipart 邮件顶层 MIME 头仍必填）；与 `body`/`raw`/`raw_hex` 互斥；详见 `pmaker://schema/multipart` |
| `raw` | string | 原始模式 | 整个内容字节裸透传（不拼头体、不归一化，成帧照常自动追加）；支持 `@file` |
| `raw_hex` | string | 原始模式 | `0x` 前缀十六进制内容字节（二进制内容）；与 `raw` 互斥 |

## 模式互斥

- **结构化模式**：`headers` 非空（必填），`body` 可空（合规空体邮件）或用 `multipart`（multipart 邮件顶层 MIME 头仍必填），`raw`/`raw_hex` 均空。`headers` 为空 → 报错（RFC 5322 邮件必有头；构造无头/缺头等畸形请用 `raw`）。重复头（如多个 `Received`）结构化模式即可表达，无需 `raw`。
- **原始模式**：`raw` 或 `raw_hex` 非空，`headers`/`body`/`multipart` 均空。
- 两种模式**互斥**；`raw` 与 `raw_hex` 互斥；`multipart` 与 `body` 互斥；全空报错。

## 畸形构造

SMTP/POP3 下的成帧（dot-stuffing + 终止符）自动完成且无法关闭；成帧相关畸形统一走
`payload`/`payload_hex` 原始字节兜底：

| 畸形类型 | 构造方式 |
|----------|----------|
| 缺 dot-stuffing（行首 `.` 未 stuff） | `payload`/`payload_hex` 承载精确字节 |
| 缺终止符 / 终止符后追加字节 | `payload`/`payload_hex` 承载精确字节 |
| 非法/缺失头、缺空行、非标换行 | `eml_data` 的 `raw` 模式（内容字节裸透传，成帧照常自动追加）或 `payload`/`payload_hex` |
| 二进制正文 | `raw_hex` 模式或 `payload_hex` |
| 头注入（CRLF in header value） | `headers` 值含 `\r\n`（裸透传不转义） |

## 协议复用

| 协议 | 用法 | 成帧（自动，不可关闭） |
|------|------|------|
| **SMTP DATA** | `stack` 里的独立 `eml_data` 层 | dot-stuffing + `.\r\n` 终止符 |
| **POP3 RETR / TOP** | `pop3_response.eml` 子结构 | dot-stuffing + `.\r\n` 终止符 |
| **IMAP FETCH / APPEND** | `imap_request.literal.eml` / `imap_response.literal.eml` 子结构 | 长度前缀 `{n}\r\n`，无 dot-stuffing、无终止符 |
