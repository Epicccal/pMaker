# imap_response —— IMAP 服务器响应(L7,走 tcp,IMAP4rev2 RFC 9051)

一条服务器响应 = 一个 `imap_response` 层,序列化为 TCP payload。IMAP 响应按 `tag` 三态定型:
具体 tag = tagged、`*` = untagged、`+` = continuation。状态组与数据组**互斥**。
通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
flows:
  - name: imap-login
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.143", ttl: 64 }
      - tcp:  { sport: 49152, dport: 143, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - imap_request: { tag: A001, command: LOGIN, args: "alice secret" }
      - from: dst
        stack:
          - imap_response: { tag: A001, status: OK, text: "LOGIN completed" }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `tag` | string | **是** | 具体 tag=tagged / `*`=untagged / `+`=continuation;具体 tag 走字符集校验(同 `imap_request`,不含 `+` 与 atom-specials) |
| `status` | string | 状态组 | `OK`/`NO`/`BAD`/`PREAUTH`/`BYE`(大小写不敏感、原样输出);tagged 仅 `OK`/`NO`/`BAD` |
| `code` | string | 状态组 | resp-text-code 方括号内内容,不做白名单(atom 兜底,开放扩展槽);**禁含 `]`** |
| `text` | string | 状态组 | resp-text 文本;tag `+` 时唯一允许字段 |
| `data` | string | 数据组 | 数据形式响应体(literal 之前的文本);**仅 `tag: "*`**;首 token 不得为 OK/NO/BAD/PREAUTH/BYE |
| `literal` | `IMAPLiteral` 子结构 | 数据组 | 嵌在 data 之后的长度前缀内容;须依附 data |
| `tail` | string | 数据组 | literal 之后的文本(如 `)` 收尾);须依附 data |

## tag 三态 + 两组分流

- **tagged(具体 tag)**:仅状态组(`status`+`code`+`text`),`status` ∈ `OK`/`NO`/`BAD`。
- **untagged(`*`)**:状态组(全部五值)**或** 数据组(`data`+`literal`+`tail`),二者互斥。
- **continuation(`+`)**:仅 `text` 允许(continue-req = `+ SP (resp-text / base64) CRLF`;`text` 可空,即 `+ \r\n` SASL 空挑战)。

**状态组**输出 `prefix status[ [code]][ SP text]\r\n`;**数据组**输出 `prefix data[ literal][tail]\r\n`
(literal 嵌在 data 与 tail 之间)。

## IMAPLiteral 子结构

同 `imap_request`(`eml`/`data`/`data_hex` 三选一、`octets` 两态覆盖、`emit`、`binary`),
**两点差异**:① 这是 server→client 方向,`sync: false`(`{n+}`)**硬错**(RFC 9051 §4.3 服务器不得发非同步 literal);
② `binary: true`(`~{n}` literal8)**仅此方向合法**(client 不发 literal8)。详见 `pmaker://schema/imap_request`。

## 组合规则

- `tag` 必填(空报错)。
- 具体 tag 经字符集校验(同 `imap_request`:非空、不含 `+` 与 atom-specials,`]` 合法)。
- `status` 与 `data` **互斥**(同设硬错)。
- `data` 的首 token(后跟 SP 或行尾,大小写不敏感)不得为 `OK`/`NO`/`BAD`/`PREAUTH`/`BYE`(封死状态响应误写进 data)。
- `data` 非空时 `tag` 必须 = `*`(tagged 响应文法上恒为状态形式)。
- `code`/`text` 不得与 `data` 同现;`literal`/`tail` 非空时 `data` 须非空(须依附数据组)。
- 状态组或数据组**至少一组非空**(全空报错);`text`/`code` 不得脱离 `status` 单独存在。
- 所有文本字段(`status`/`code`/`text`/`data`/`tail`)禁含 `\r` / `\n`;`code` 额外禁含 `]`。

## 一致性告警(软告警)

- `literal.octets` 显式值与实际字节数不符 → 软告警(`imap.literal-octets-mismatch`;「计数撒谎」,不阻断)。

## 静默陷阱

- **tagged 响应只能 OK/NO/BAD**:`PREAUTH`/`BYE` 只能 untagged(`tag: "*"`),写进具体 tag 会被拦。
- **`data` 只在 `tag: "*"` 下可用**:tagged 响应恒为状态形式,数据响应必然 untagged。
- **`data` 首 token 不能是状态词**:想发 `* OK [UIDVALIDITY 1] ...` 走 `status`+`code`+`text`,
  不能写进 `data`(首 token `OK` 会被拦);缺空格等非标间距走 `payload` / `payload_hex`。
- **`literal.eml` 不做 dot-stuffing / 终止符**:IMAP 靠 `{n}` 长度前缀定界,与 SMTP/POP3 不同。
- **continuation `+` 只认 `text`**:带 `status`/`data`/`literal` 会被拦;裸 `+`(无 SP)走 `payload` / `payload_hex`。
- **`code` 不做白名单**:`code: UIDVALIDITY 1` 原样落值(atom 兜底),扩展槽开放;唯一硬约束是不含 `]`。
- **`status` 原样输出**:写 `ok` 是合法构造(大小写不敏感,是合规测试点),不是错误。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 非标间距状态行(如 `* OK[...]` 缺空格) | `payload` / `payload_hex` |
| 非标 tag | `payload` / `payload_hex` |
| literal 计数撒谎 | `literal.octets: 9999`(原样落值,出软告警) |
| literal8 `~{n}` 二进制内容 | `literal: { binary: true, data_hex: "0x...", sync: true }` |
| 裸 `+`(无 SP 续行) | `payload` / `payload_hex` |
| 小写 / 混合大小写 status | `status: ok`(原样输出) |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `需要 tag(tag / "*" / "+")` | `tag` 必填,三态之一 |
| `status 与 data 互斥` | 状态响应用 `status`+`code`+`text`,数据响应用 `data`+`literal`+`tail`,二选一 |
| `data 仅 untagged 响应(tag="*")可用` | tagged 响应恒为状态形式;数据响应把 `tag` 改成 `*` |
| `data 的首 token 不得是 OK/NO/BAD/PREAUTH/BYE` | 状态响应改走 `status`+`code`+`text`;非标间距走 `payload` / `payload_hex` |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.143" }
      - tcp:  { sport: 49152, dport: 143, flags: [PSH, ACK] }
      - imap_response: { status: OK, text: "x" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.143" }
      - tcp:  { sport: 49152, dport: 143, flags: [PSH, ACK] }
      - imap_response: { tag: A001, status: OK, data: "1 EXISTS" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.143" }
      - tcp:  { sport: 49152, dport: 143, flags: [PSH, ACK] }
      - imap_response: { tag: A001, data: "1 EXISTS" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.143" }
      - tcp:  { sport: 49152, dport: 143, flags: [PSH, ACK] }
      - imap_response: { tag: "*", data: "OK [UIDVALIDITY 1] UIDs valid" }
```

## 相关

`pmaker://schema/imap_request`、`pmaker://schema/eml_data`、`pmaker://schema/_why_imap_grouping`、`pmaker://schema/tcp_session`、`pmaker://examples`
