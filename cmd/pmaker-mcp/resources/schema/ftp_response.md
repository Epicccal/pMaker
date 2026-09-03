# ftp_response —— FTP 控制连接响应(L7,走 tcp)

一条响应 = 一个 `ftp_response` 层,序列化为 TCP payload。单行 `code message\r\n`;
多行续行(RFC 959 §4.2)首行 `code-text`、末行 `code[ SP text]`。通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
flows:
  - name: ftp-greeting
    stack:
      - eth:  { src: "66:77:88:99:aa:bb", dst: "00:11:22:33:44:55" }
      - ipv4: { src: "10.0.0.21", dst: "10.0.0.10", ttl: 64 }
      - tcp:  { sport: 21, dport: 49152, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - ftp_response: { code: 220, message: "FTP server ready" }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `code` | int | **是** | 三位 100-599(首位 1-5);越界报错并引导 `payload`/`payload_hex` |
| `message` | string | 与 `lines` **二选一** | 单行:`code message\r\n`;`message` 为空则裸 `code\r\n` |
| `lines` | []string | 与 `message` **二选一** | 多行续行:首行 `code-`、中间裸文本、末行 `code[ SP text]` |

`message` 与 `lines` 互斥,必须有其一。

## 组合规则

- `code` 必须是三位 100-599(首位 1-5);`22` / 负数 / `>999` 报错。不强制必须是 RFC 已定义码,
  保留扩展(如 `999`),但位数非法会被拦。
- `message` 与 `lines` 至多一个,且必须有其一(裸 `code` 走 `payload` / `payload_hex`)。
- 多行续行的**行边界由 builder 注入**:每个 `lines` 元素 = 一行,builder 加 `\r\n` 与 `code-` / `code ` 前缀。

## 静默陷阱

- **`lines` 元素内嵌 `\n` 不会被识别为行边界**:builder 把每个元素当一行、整体 join,
  元素里的 `\r\n` 会原样落进字节流,产出与"多一行"预期不符的包且无告警。
  要构造含嵌入换行的续行走 `payload` / `payload_hex`。
- **`code` 不校验是否为 RFC 已定义码**:`299`、`999` 照单全收(扩展空间),只要位数合法。
  想构造完全非法的响应码(如两位 `22`)会被拦 —— 那种走 `payload_hex`。
- 末行空文本(`lines` 末元素为 `""`)产出 `code \r\n`(code + 空格),RFC 959 合规,
  但与"无末行文本"语义不同,不会被丢弃。
- **PASV 227 / EPSV 229 响应文本会被解析做端口一致性告警**:六元组 / `(|||port|)` 解析失败
  只产软告警不拦;解析成功但与数据流 dst 不一致也只告警。故意构造不一致是合法用例。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 非三位 / 越界响应码 | `payload` / `payload_hex` |
| 缺 `code-` 续行前缀、非标多行格式 | `payload` / `payload_hex` |
| 续行元素含嵌入换行 | `payload` / `payload_hex` |
| 末行无空格(`code\r\n` 而非 `code \r\n`) | `payload` / `payload_hex` |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `code 22 非法,FTP 响应码须为三位 100-599` | `code` 须三位 100-599。要构造非法位数走 `payload` / `payload_hex` |
| `message 与 lines 只能配置一个` | 单行用 `message`,多行用 `lines`,二选一 |
| `需要 message 或 lines` | 二者必有其一。裸 `code` 走 `payload` / `payload_hex` |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.21", dst: "10.0.0.10" }
      - tcp:  { sport: 21, dport: 49152, flags: [PSH, ACK] }
      - ftp_response: { code: 22, message: "x" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.21", dst: "10.0.0.10" }
      - tcp:  { sport: 21, dport: 49152, flags: [PSH, ACK] }
      - ftp_response: { code: 220, message: "hi", lines: ["a"] }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.21", dst: "10.0.0.10" }
      - tcp:  { sport: 21, dport: 49152, flags: [PSH, ACK] }
      - ftp_response: { code: 220 }
```

## 相关

`pmaker://schema/ftp_request`、`pmaker://schema/tcp_session`、`pmaker://schema/payload_hex`
