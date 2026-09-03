# eml_data —— RFC 5322 邮件内容(协议无关内容层,L7 走 tcp)

一封 RFC 5322 邮件内容(headers + body)= 一个 `eml_data` 层,序列化为 TCP payload 字节。
**协议无关的内容层**:只产 RFC 5322 内容字节,**不含成帧**。成帧(framing)由承载它的传输协议
强制,`eml_data` 自身没有成帧开关。通则见 `pmaker://schema/_conventions`。

- **SMTP DATA**(RFC 5321 §4.5.2)/ **POP3 RETR**(RFC 1939 §3):写成独立 `eml_data` 层或
  `pop3_response.eml`,接入层强制 dot-stuffing + 追加 `<CRLF>.<CRLF>` 终止符,**无 opt-out**;
  缺 dot-stuffing / 缺终止符等成帧畸形走 `payload` / `payload_hex`。
- **IMAP**(RFC 9051,FETCH / APPEND):写成 `imap_request.literal.eml` / `imap_response.literal.eml`,
  内容字节被加上长度前缀 `{n}\r\n`,**不做 dot-stuffing、不加终止符**(IMAP 靠长度定界)。

## 骨架

```yaml
link_type: ethernet
flows:
  - name: smtp-mail
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.25", ttl: 64 }
      - tcp:  { sport: 49152, dport: 25, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - smtp_request: { verb: MAIL, from: alice@example.com }
      - from: src
        stack:
          - eml_data:
              headers:
                From: alice@example.com
                To: bob@example.net
                Subject: Hello
                Date: "Thu, 01 Jan 2024 00:00:00 +0000"
                Content-Type: "text/plain; charset=utf-8"
              body: "This is the email body.\r\nSecond line.\r\n"
```

headers 按 YAML 声明顺序输出 + 空行 + body,SMTP/POP3 接入层再追加 dot-stuffing + `.\r\n`。

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `headers` | map | 结构化模式必填 | 邮件头(RFC 5322),保留声明顺序输出为 `Key: Value\r\n`,支持重复头(多个 `Received`);值含 `\r\n`+空白=folding(合规),`\r\n`+非空白=头注入(畸形,裸透传不转义) |
| `body` | string | 结构化模式可选 | 邮件正文体;可空(合规空体);可用 `@file(...)` 注入;与 `multipart` 互斥;**结构化模式自动归一化换行**(裸 `\n` → `\r\n`,兼容 YAML `|` 块标量;`raw` 模式不归一化) |
| `multipart` | 子结构 | 结构化模式可选 | MIME multipart body(RFC 2046)作正文(multipart 邮件顶层 MIME 头仍必填);与 `body`/`raw`/`raw_hex` 互斥;详见 `pmaker://schema/multipart` |
| `raw` | string | 原始模式 | 整个内容字节裸透传(不拼头体、不归一化,成帧照常自动追加);可用 `@file(...)` 注入外部 `.eml` 文件 |
| `raw_hex` | string | 原始模式 | `0x` 前缀十六进制内容字节(二进制内容);与 `raw` 互斥;**不可用 `@file`** |

## 组合规则

- **结构化模式**(`headers`/`body`/`multipart` 任一非空):`headers` 必填(RFC 5322 邮件必有头);
  `body` 可空;`multipart` 与 `body` 互斥;`raw`/`raw_hex` 须空。
- **原始模式**(`raw`/`raw_hex` 任一非空):`headers`/`body`/`multipart` 须空;`raw` 与 `raw_hex` 互斥。
- 两种模式**互斥**;全空报错。
- `raw_hex` 须为合法 `0x` 前缀十六进制。

## 静默陷阱

- **成帧是接入层职责,内容层无开关**:SMTP/POP3 下 dot-stuffing + 终止符强制追加且无法关闭;
  IMAP 下加 `{n}\r\n` 前缀无 dot-stuffing。把 SMTP 的成帧心智搬进 IMAP(或反之)会出错。
- **`raw` 注入外部 `.eml` 要当心双重终止符**:邮件客户端另存的 `.eml`、Wireshark「Export Objects → IMF」
  导出的邮件**不含** `.\r\n`(那是传输成帧),可直接 `@file` 注入;但 Wireshark「Follow TCP Stream」这类
  保留完整传输流的导出**含**发送方写入的 `.\r\n`,此时接入层再追加一次 → 双重终止符,应改用
  `payload` / `payload_hex` 精确控制成帧字节。
- **`body` 结构化模式归一化换行,`raw` 不归一化**:`body: "a\nb"` 会变成 `a\r\nb`(便利);
  但 `raw` 保留精确字节(构造非标换行畸形)。`raw_hex` 同样不归一化。
- **headers 值裸透传不转义**:值含 `\r\n`+非空白 = 头注入,原样落值不拦 —— 是可用的注入构造点,
  也是易误踩点(合规 folding 是 `\r\n`+空白)。
- **缺 dot-stuffing / 缺终止符走不了 `eml_data`**:成帧畸形统一走 `payload` / `payload_hex`(接入层
  会强制成帧,关不掉)。
- **`raw_hex` 不可用 `@file`**:hex 字段注入原始字节会破坏 hex 语义;二进制内容用 `raw` + `@file`,
  或直接 `payload_hex`。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 缺 dot-stuffing / 缺终止符 / 终止符后追加字节 | `payload` / `payload_hex`(成帧无法关闭) |
| 无头 / 缺头 / 非法头 / 缺空行 / 非标换行 | `raw`(内容裸透传,成帧照常追加)或 `payload` / `payload_hex` |
| 二进制正文 | `raw_hex` 或 `payload_hex` |
| 头注入(CRLF in header value) | `headers` 值含 `\r\n`+非空白(裸透传) |
| 双重终止符 / 自带终止符 | `payload` / `payload_hex`(不走 `eml_data`) |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `headers/body/multipart 与 raw/raw_hex 不可同设` | 结构化模式与原始模式互斥。畸形内容(无头等)走 `raw`/`raw_hex`,规范内容走 `headers`+`body` |
| `需要 headers/body/multipart 或 raw/raw_hex` | 内容全空无意义。缺成帧的裸字节走 `payload` / `payload_hex` |
| `结构化模式需要 headers 非空` | 结构化模式邮件必有头。构造无头 / 缺头畸形改用 `raw` 或 `raw_hex` |
| `multipart 与 body 不可同设` | multipart 本身就是正文,二选一 |
| `raw 与 raw_hex 只能配置一个` | 原始模式二选一 |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 25, flags: [PSH, ACK] }
      - eml_data: { headers: { From: "a@b" }, raw: "x" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 25, flags: [PSH, ACK] }
      - eml_data: {}
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 25, flags: [PSH, ACK] }
      - eml_data: { body: "just body no headers" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 25, flags: [PSH, ACK] }
      - eml_data:
          headers: { From: "a@b" }
          body: "x"
          multipart: { boundary: "b" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 25, flags: [PSH, ACK] }
      - eml_data: { raw: "x", raw_hex: "0x41" }
```

## 协议复用

| 协议 | 用法 | 成帧(自动,不可关闭) |
|------|------|------|
| **SMTP DATA** | `stack` 里的独立 `eml_data` 层 | dot-stuffing + `.\r\n` 终止符 |
| **POP3 RETR / TOP** | `pop3_response.eml` 子结构 | dot-stuffing + `.\r\n` 终止符 |
| **IMAP FETCH / APPEND** | `imap_request.literal.eml` / `imap_response.literal.eml` | 长度前缀 `{n}\r\n`,无 dot-stuffing、无终止符 |

## 相关

`pmaker://schema/smtp_request`、`pmaker://schema/pop3_response`、`pmaker://schema/imap_request`、
`pmaker://schema/imap_response`、`pmaker://schema/multipart`、`pmaker://examples`
