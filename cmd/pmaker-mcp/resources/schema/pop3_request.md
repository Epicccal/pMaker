# pop3_request —— POP3 客户端命令(L7,走 tcp)

一条 POP3 命令 = 一个 `pop3_request` 层,序列化为 TCP payload `COMMAND[ args]\r\n`。
命令无结构化信封(不像 SMTP MAIL/RCPT),统一走 `command` + `args` 扁平风格(对齐 `ftp_request`)。
`command` 原样输出(不强制大写)。通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
flows:
  - name: pop3-retr
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.110", ttl: 64 }
      - tcp:  { sport: 49152, dport: 110, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - pop3_request: { command: USER, args: alice }
      - from: src
        stack:
          - pop3_request: { command: RETR, args: "1" }
      - from: src
        stack:
          - pop3_request: { command: QUIT }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `command` | string | **是** | RFC 1939 核心 + 扩展(大小写不敏感);未列入报错并引导 `payload`/`payload_hex` |
| `args` | string | 视命令 | 命令参数(USER 邮箱名、RETR msg#、TOP 的 `msg# n`、APOP 的 `name digest`、AUTH 机制);有/无按下表;**不能含 `\r` / `\n`** |

`command` 原样输出,保留 `user`/`RETR`/`Retr` 等大小写构造能力(RFC 1939 §3 命令大小写不敏感,是合规测试点)。

**已知命令**:RFC 1939 核心(USER/PASS/APOP/STAT/LIST/RETR/DELE/NOOP/RSET/TOP/UIDL/QUIT)
+ 扩展(CAPA/STLS/AUTH)。

## command 参数要求

- **必带 args**:USER / PASS / APOP / RETR / DELE / TOP / AUTH
- **禁带 args**:STAT / NOOP / RSET / QUIT / CAPA / STLS
- **可选 args**:LIST / UIDL(无参 = 多行响应;有参 = msg# 单行响应)

## 组合规则

- `command` 非空且在已知表内;未知 / 私有命令报错,改走 `payload` / `payload_hex`。
- `args` 不能含 `\r` / `\n`(会注入额外命令行);有/无按命令策略校验。
- `args` 不做内容语义校验(避免过度约束畸形构造)。

## 静默陷阱

- **`pop3_request` 产不出 SASL 续行所需的裸 base64 行**:RFC 1734 §3 AUTH 后续往返是
  "a line containing a BASE64 encoded string"(无命令前缀),而 `command` 恒输出。客户端
  SASL 续行响应须用 `payload` / `payload_hex` 承载裸 base64。
- **`command` 拼错是硬错**(如 `RETER`),无数字兜底 —— 这点与 `dns.type` 的数字回退不同。
- 命令大小写不敏感是 POP3 的合规测试点:写 `user` / `+ok` 是合法构造,不是错误。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 私有 / 非标命令 | `payload` / `payload_hex` |
| 小写 / 混合大小写命令 | `command: user`(原样输出) |
| SASL 续行裸 base64 行 | `payload` / `payload_hex`(`command` 恒输出,产不出裸行) |
| `args` 含换行(注入多命令行) | 被校验拦下,改走 `payload_hex` |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `需要 command` | `command` 必填。裸字节走 `payload` / `payload_hex` |
| `未知 POP3 命令` | 命令不在已知表内。私有 / 非标命令改用 `payload` / `payload_hex` |
| `RETR 需要 args` | 必带 args 的命令缺参数;该命令的畸形(非标空格等)走 `payload` / `payload_hex` |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.110" }
      - tcp:  { sport: 49152, dport: 110, flags: [PSH, ACK] }
      - pop3_request: { args: alice }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.110" }
      - tcp:  { sport: 49152, dport: 110, flags: [PSH, ACK] }
      - pop3_request: { command: RETER }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.110" }
      - tcp:  { sport: 49152, dport: 110, flags: [PSH, ACK] }
      - pop3_request: { command: RETR }
```

## 相关

`pmaker://schema/pop3_response`、`pmaker://schema/tcp_session`、`pmaker://examples`
