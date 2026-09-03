# pop3_response —— POP3 服务器响应(L7,走 tcp)

一条响应 = 一个 `pop3_response` 层,序列化为 TCP payload。单行 `+OK`/`-ERR [text]\r\n`,
或多行(`status` 行 + 正文 + `<CRLF>.<CRLF>` 终止符);SASL 续行挑战为 `+ [base64]\r\n`
(RFC 1734/4954,单字符 `+` 而非 `+OK`)。`status` 原样输出(不强制大写)。
通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
flows:
  - name: pop3-greeting
    stack:
      - eth:  { src: "66:77:88:99:aa:bb", dst: "00:11:22:33:44:55" }
      - ipv4: { src: "10.0.0.110", dst: "10.0.0.10", ttl: 64 }
      - tcp:  { sport: 110, dport: 49152, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - pop3_response: { status: "+OK", message: "POP3 server ready" }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `status` | string | **是** | `+OK` / `-ERR` / `+`(大小写不敏感、**原样输出**);`+` = RFC 1734/4954 SASL 续行挑战 |
| `message` | string | 条件 | 状态行附带文本;**不能含 `\r` / `\n`** |
| `lines` | []string | 条件 | 多行普通行(LIST/UIDL/CAPA);**每元素 = 一行,不应含换行符**——行边界由 builder 注入 |
| `eml` | `eml_data` 子结构 | 条件 | 多行 RFC 5322 正文(RETR/TOP)→ `pmaker://schema/eml_data` |

`message` / `lines` / `eml` 三者至少其一非空;`lines` 与 `eml` 互斥。

## 组合规则(硬错)

- `status` 非空且为 `+OK` / `-ERR` / `+`(大小写不敏感);非标状态指示符走 `payload` / `payload_hex`。
- `lines` 与 `eml` 互斥(多行正文二选一)。
- `message` 可与 `lines` / `eml` 组合 → 多行响应首行带说明文本(RFC 1939 §3 合法形态,
  如 LIST 的 `+OK 2 messages (320 octets)`、CAPA 的 `+OK Capability list follows`)。
- **多行正文(`lines` / `eml`)仅 `+OK` 可用**:`-ERR` 永远单行,`+` 是单行 SASL 挑战,
  二者搭配 `lines` / `eml` 会被拦。
- `message` / `lines` 元素不能含 `\r` / `\n`(会注入额外响应行)。
- `eml` 非空时委托 `eml_data` 子结构校验(见 `pmaker://schema/eml_data`)。

## 静默陷阱

- **`lines` 元素内嵌 `\n` 不会成为行边界**,dot-stuffing 也不在该位置生效 → 产出的字节与
  预期不符且无告警。需要嵌入换行走 `payload` / `payload_hex`。
- **`message` 内嵌 `\r` / `\n` 会被校验拦下**(与 `lines` 不同,`message` 是硬错而非静默)。
- 成帧(dot-stuffing + `<CRLF>.<CRLF>` 终止符)由接入层强制追加,**无 opt-out**;
  `status` 行本身不参与 dot-stuff(只有其后的多行正文才 stuff)。缺终止符 / 缺 dot-stuffing
  的成帧畸形走 `payload` / `payload_hex`。
- CAPA 响应用 `lines`(能力标签不区分大小写,如 `SASL CRAM-MD5 KERBEROS_V4`、`STLS`,RFC 2449)。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 非标状态指示符(`+OKAY`) | `payload` / `payload_hex` |
| 裸 status 行(无 text 无正文) | `payload` |
| 缺终止符 / 缺 dot-stuffing | `payload_hex`(成帧自动追加且不可关闭) |
| 客户端 SASL 续行(裸 base64 行) | `payload`——`pop3_request.command` 恒输出,产不出裸行 |
| `lines` 元素含嵌入换行 | `payload` / `payload_hex` |

## 报错 → 改法

`status` 非法一条**不收录**——校验器文案已自带「非标状态指示符请用 payload / payload_hex」。
下面两条改法有增量信息(指向另一个字段):

| 报错含 | 改法 |
|--------|------|
| `lines 与 eml 互斥,只能配置一个多行正文` | 多行正文二选一;首行说明文本改用 `message`,它可与任一多行正文共存 |
| `永远单行(RFC 1939 §3),不接受多行正文` | 想给 `-ERR` 补说明文本用 `message`;确要非标多行 `-ERR` 走 `payload_hex` |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.110", dst: "10.0.0.10" }
      - tcp:  { sport: 110, dport: 49152, flags: [PSH, ACK] }
      - pop3_response: { status: "+OK", lines: ["1 1200"], eml: { headers: { From: "a@b" } } }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.110", dst: "10.0.0.10" }
      - tcp:  { sport: 110, dport: 49152, flags: [PSH, ACK] }
      - pop3_response: { status: "-ERR", lines: ["boom"] }
```

## 相关

`pmaker://schema/pop3_request`、`pmaker://schema/eml_data`、`pmaker://schema/tcp_session`、`pmaker://examples/pop3/retr_file.yaml`、`pmaker://examples/pop3/auth_sasl.yaml`
