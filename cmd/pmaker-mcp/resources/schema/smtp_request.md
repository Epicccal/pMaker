# smtp_request —— SMTP 信封命令(L7,走 tcp)

一条信封命令 = 一个 `smtp_request` 层,序列化为 TCP payload。MAIL/RCPT 走结构化信封路径
(`from`/`to` + `params`),其余 verb 用 `args` 携带普通参数。verb 原样输出(不强制大写)。
通则见 `pmaker://schema/_conventions`。

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
          - smtp_request: { verb: EHLO, args: mail.example.com }
      - from: src
        stack:
          - smtp_request: { verb: MAIL, from: sender@example.com, params: { SIZE: "1000", SMTPUTF8: "" } }
      - from: src
        stack:
          - smtp_request: { verb: RCPT, to: rcpt@example.com }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `verb` | string | **是** | EHLO/HELO/MAIL/RCPT/DATA/QUIT/RSET/NOOP/VRFY/EXPN/HELP/AUTH/STARTTLS/BDAT/ETRN/ATRN(+历史 SEND/SOML/SAML/TURN);非标走 `payload`/`payload_hex` |
| `from` | string(指针) | MAIL 必填 | 反向路径;省略(nil)报错;`""`→`<>`(退信);`"addr"`→`<addr>` |
| `to` | string | RCPT 必填 | 前向路径,须非空 |
| `params` | map | 仅 MAIL/RCPT | 扩展参数,保留 YAML 声明顺序、支持重复键(多 `ORCPT`);空值=裸 flag(`SMTPUTF8`),非空=`KEY=VALUE` |
| `args` | string | 非 MAIL/RCPT verb | 普通参数(EHLO 域名、AUTH 机制+凭证、BDAT chunk-size);MAIL/RCPT 禁用 |

`verb` 原样输出(不强制大写);结构化路径自动规范 `FROM:`/`TO:` 关键字与 `<>` 包裹。

## verb 参数要求

- **必带 args**:EHLO/HELO/VRFY/EXPN/AUTH/BDAT/ETRN/SEND/SOML/SAML
- **禁带 args**:DATA/RSET/QUIT/STARTTLS/TURN
- **可选 args**:NOOP/HELP/ATRN
- `params` 仅 MAIL/RCPT 有效,给其他 verb 报错。

## 组合规则

- MAIL 须配 `from`(指针三态:nil 报错 / `""`→`<>` / `"addr"`→`<addr>`),禁 `to` / `args`。
- RCPT 须配 `to`(非空),禁 `from` / `args`。
- 非 MAIL/RCPT verb 禁 `from` / `to` / `params`,`args` 按上表策略判有/无。
- DATA 正文用独立的 `eml_data` 层结构化构造(SMTP 自动 dot-stuffing + 终止符)。

## 静默陷阱

- **`from` / `to` / `args` 裸透传不转义**:地址里的 CRLF 注入(`from: "a\r\nDATA"`)会原样
  落进字节流,产出额外命令行,校验器不拦。这是可用的注入构造点,也是易误踩点。
- **`params` 值裸透传**:`params: { SIZE: "1000\r\nX" }` 同样不拦换行,会注入额外行。
- verb 拼错(`HELO`→`HELO` 无错,但 `Helo` 也合规;`HELO`→`HELO0` 是硬错)—— 非标 / 私有 verb
  走 `payload` / `payload_hex`,**不走 `args` 兜底**。
- MAIL/RCPT 的结构性畸形(缺 `<>`、非标空格、`FROM`/`TO` 大小写非标、缺冒号)结构化路径
  表达不了,校验器会拦 verb 但不拦地址内容畸形 —— 后者走结构化路径即可(裸透传)。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 私有 / 非标 verb | `payload` / `payload_hex` |
| 小写 / 混合大小写 verb | `verb: helo`(原样输出) |
| CRLF 注入(地址或参数含换行) | `from` / `to` / `args` / `params` 值带 `\r\n`(裸透传) |
| 缺 `<>` / 非标 `FROM` 关键字 | `payload` / `payload_hex`(结构化路径会规范掉) |
| DATA 正文 dot-stuffing 畸形 | `eml_data` 的 `raw` / `raw_hex`,或 `payload_hex` |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `需要 verb` | `verb` 必填。裸字节走 `payload` / `payload_hex` |
| `MAIL 需要 from` | MAIL 须配 `from`;退信(null reverse path)显式写 `from: ""` |
| `RCPT 需要 to` | RCPT 须配 `to` 且非空;空路径畸形走 `payload` / `payload_hex` |
| `EHLO 需要 args` | 必带 args 的 verb 缺参数;该 verb 的畸形(带非标空格等)走 `payload` / `payload_hex` |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.25" }
      - tcp:  { sport: 49152, dport: 25, flags: [PSH, ACK] }
      - smtp_request: { args: mail.example.com }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.25" }
      - tcp:  { sport: 49152, dport: 25, flags: [PSH, ACK] }
      - smtp_request: { verb: MAIL, to: "x@y" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.25" }
      - tcp:  { sport: 49152, dport: 25, flags: [PSH, ACK] }
      - smtp_request: { verb: RCPT }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.25" }
      - tcp:  { sport: 49152, dport: 25, flags: [PSH, ACK] }
      - smtp_request: { verb: EHLO }
```

## 相关

`pmaker://schema/smtp_response`、`pmaker://schema/eml_data`、`pmaker://schema/tcp_session`、`pmaker://examples`
