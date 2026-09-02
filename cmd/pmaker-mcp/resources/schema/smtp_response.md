# smtp_response —— SMTP 响应(L7,走 tcp)

单行 / 多行遵循 RFC 5321 §4.2 的 Reply-line 文法:续行带 `code-` 前缀,末行 `code[ SP text]`。
通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
flows:
  - name: smtp-greeting
    stack:
      - eth:  { src: "66:77:88:99:aa:bb", dst: "00:11:22:33:44:55" }
      - ipv4: { src: "10.0.0.25", dst: "10.0.0.10", ttl: 64 }
      - tcp:  { sport: 25, dport: 49152, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - smtp_response: { code: 220, message: "mail.example.com ESMTP ready" }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `code` | int | **是** | 200-559(SMTP 无 1xx,首位 2-5;十位须 0-5);非标走 `payload`/`payload_hex` |
| `message` | string | 与 `lines` **二选一** | 单行:`code message\r\n`;为空则裸 `code\r\n` |
| `lines` | []string | 与 `message` **二选一** | 多行续行:续行 `code-`、末行 `code[ SP text]`;空文本行如实输出(合规) |

`message` 与 `lines` 互斥,必须有其一。

## 组合规则

- `code` 按 RFC 5321 §4.2 逐位校验:百位 2-5、十位 0-5、个位 0-9。`260` 落在 200-559 区间内但
  十位越界,会被拦。非标响应码(非法位数 / 越界)走 `payload` / `payload_hex`。
- `message` 与 `lines` 至多一个,且必须有其一(裸 `code` 走 `payload` / `payload_hex`)。
- 多行续行的行边界由 builder 注入:每个 `lines` 元素 = 一行,续行加 `code-`、末行加 `code ` 前缀。

## 静默陷阱

- **`lines` 元素内嵌 `\r\n` 不会被识别为行边界**:builder 把每个元素当一行、整体 join,
  元素里的换行会原样落进字节流,产出与预期不符的包且无告警。要构造含嵌入换行的续行走
  `payload` / `payload_hex`。
- **`code` 不校验是否为 RFC 已定义码**:`259`、`559` 照单全收(只要逐位合法)。想构造完全
  非法的响应码(如 `99`)会被拦 —— 那种走 `payload_hex`。
- 末行空文本(`lines` 末元素为 `""`)产出纯 `code\r\n`(无尾随空格),RFC 5321 严格合规;
  续行空文本产出 `code-\r\n`,也合规。空文本不会被丢弃。
- SMTP **无 1xx**(与 HTTP 不同);写 `100` 会被百位校验拦下。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 非法响应码(1xx / 十位越界 / 非三位) | `payload` / `payload_hex` |
| 缺 `code-` 续行前缀、非标多行格式 | `payload` / `payload_hex` |
| 续行元素含嵌入换行 | `payload` / `payload_hex` |
| 末行带尾随空格(`code \r\n`) | `payload` / `payload_hex`(结构化路径末行无文本时无尾随空格) |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `code 260 非法,SMTP 响应码十位须 0-5` | `code` 须百位 2-5、十位 0-5、个位 0-9。非法码走 `payload` / `payload_hex` |
| `message 与 lines 只能配置一个` | 单行用 `message`,多行用 `lines`,二选一 |
| `需要 message 或 lines` | 二者必有其一。裸 `code` 走 `payload` / `payload_hex` |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.25", dst: "10.0.0.10" }
      - tcp:  { sport: 25, dport: 49152, flags: [PSH, ACK] }
      - smtp_response: { code: 260, message: "x" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.25", dst: "10.0.0.10" }
      - tcp:  { sport: 25, dport: 49152, flags: [PSH, ACK] }
      - smtp_response: { code: 250, message: "hi", lines: ["a"] }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.25", dst: "10.0.0.10" }
      - tcp:  { sport: 25, dport: 49152, flags: [PSH, ACK] }
      - smtp_response: { code: 250 }
```

## 相关

`pmaker://schema/smtp_request`、`pmaker://schema/eml_data`、`pmaker://schema/tcp_session`
