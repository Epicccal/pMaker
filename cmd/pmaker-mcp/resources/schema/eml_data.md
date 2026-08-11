# eml_data —— RFC 5322 邮件内容(协议无关,L7 走 tcp)

一封 RFC 5322 邮件内容(headers + body)= 一个 `eml_data` 层，序列化为 TCP payload 字节。
协议无关：RFC 5322 内容是 SMTP/POP3/IMAP 的共同核心，framing 由 `dot_stuff`/`dot_terminate` 开关控制。
SMTP DATA（RFC 5321）与 POP3 RETR（RFC 1939）用行框架（dot-stuffing + `<CRLF>.<CRLF>` 终止符），
IMAP FETCH（RFC 9051）用长度前缀字面量（`{n}\r\n` + bytes，无 dot-stuffing/终止符）。

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

序列化结果（headers 按 key 字典序输出）：

```
Content-Type: text/plain; charset=utf-8\r\n
Date: Thu, 01 Jan 2024 00:00:00 +0000\r\n
From: alice@example.com\r\n
Message-ID: <abc@example.com>\r\n
MIME-Version: 1.0\r\n
Subject: Hello\r\n
To: bob@example.net\r\n
\r\n
This is the email body.\r\n
Second line.\r\n
.\r\n
```

## 原始模式（裸透传 EML，构造畸形）

```yaml
- eml_data:
    raw: "From: alice@example.com\r\nTo: bob\r\n\r\nbody\r\n.\r\n"
    dot_terminate: off   # raw 已含终止符，不重复追加
- eml_data:
    raw: "@file(assets/email.eml)"   # @file 注入外部 EML 文件
    dot_terminate: off
- eml_data:
    raw_hex: "0x466f6f"              # 二进制正文（hex）
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `headers` | map[string]string | 结构化模式 | 邮件头（RFC 5322），按 key 字典序输出为 `Key: Value\r\n`；不支持重复头/有序头（用 `raw`）；值含 `\r\n`+空白=folding，`\r\n`+非空白=头注入 |
| `body` | string | 结构化模式 | 邮件正文体；支持 `@file(path)` 注入；headers 与 body 间自动插空行；行结束符不自动归一化（须自行确保 `\r\n`） |
| `raw` | string | 原始模式 | 整个正文字节裸透传（不拼头体、不做 dot-stuffing，终止符由 `dot_terminate` 控制）；支持 `@file` |
| `raw_hex` | string | 原始模式 | `0x` 前缀十六进制正文字节（二进制正文）；与 `raw` 互斥 |
| `dot_stuff` | string | 可选 | `auto`（缺省，等同 on）/ `on` / `off`：行首 `.` → `..`（RFC 5321 §4.5.2 / RFC 1939 §3） |
| `dot_terminate` | string | 可选 | `auto`（缺省，等同 on）/ `on` / `off`：是否追加终止符 `<CRLF>.<CRLF>` |

## 模式互斥

- **结构化模式**：`headers` 和/或 `body` 非空，`raw`/`raw_hex` 均空。
- **原始模式**：`raw` 或 `raw_hex` 非空，`headers`/`body` 均空。
- 两种模式**互斥**；`raw` 与 `raw_hex` 互斥；全空报错。

## 畸形构造

| 畸形类型 | 构造方式 |
|----------|----------|
| 缺 dot-stuffing | `dot_stuff: off` + body 行首含 `.` |
| 缺终止符 | `dot_terminate: off` |
| 非法/缺失头、缺空行、非标换行、重复头 | `raw` 模式裸透传 |
| 二进制正文 | `raw_hex` 模式 |
| 头注入（CRLF in header value） | `headers` 值含 `\r\n`（裸透传不转义） |
| 终止符后追加字节 | `raw` + `dot_terminate: off`，raw 含 `.\r\n` 后接额外字节 |

## 协议复用

| 协议 | 用法 | 开关 |
|------|------|------|
| **SMTP DATA** | 独立层栈层，`auto` 默认 on，产出完整 DATA 内容（含 `.\r\n`） | `dot_stuff: auto`、`dot_terminate: auto` |
| **POP3 RETR**（未来） | 独立层栈层，`auto` 默认 on，产出完整 RETR 内容 | 同上 |
| **IMAP FETCH**（未来） | 嵌套在 `imap_response.literal_eml`，IMAP builder 自动覆写为 `off`，产出纯 RFC 5322 字节（无 stuffing/终止符），由 IMAP builder 包装 `{n}\r\n` | 由 builder 强制 `off` |
