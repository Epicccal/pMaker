# multipart —— MIME multipart body(子结构,非层)

`multipart` 描述一个 MIME multipart 体(RFC 2046),作 **HTTP** 或 **EML** 的 **body**。
**不是独立层**,不能单独出现在 `stack` 里;嵌在 `http_request`/`http_response`/`eml_data` 内部
作为 `multipart` 子字段。boundary 须与父层 `Content-Type` 头的 `boundary=` 一致(不一致出软告警)。
通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
flows:
  - name: upload
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - http_request:
              method: POST
              url: /upload
              auto_content_length: true
              headers:
                Content-Type: "multipart/form-data; boundary=----=_pMaker_0001"
                Content-Length: 0
              multipart:
                boundary: "----=_pMaker_0001"
                parts:
                  - headers:
                      Content-Disposition: 'form-data; name="field1"'
                    body: "value1"
```

`auto_content_length: true` 原位覆盖占位 `Content-Length: 0` 为 multipart 实际字节长度。

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `boundary` | string | 否 | 分界符;空 → 确定性默认 `----=_pMaker_0001`。非空须符合 RFC 2046 §5.1.1(长度 1-70、字符集 `0-9A-Za-z'()+_,.-/:=?` 与空格,空格不结尾) |
| `parts` | []Part | **是** | 至少 1 个 part;空报错 |

### part 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `headers` | map | 否 | part 头(`Content-Disposition`/`Content-Type`/`Content-Transfer-Encoding`…),保留声明顺序、支持重复头 |
| `body` | string | 否 | part 体;可用 `@file(...)` 注入文件内容(文本或二进制附件);与 `body_hex` 互斥 |
| `body_hex` | string | 否 | part 体(`0x` 前缀十六进制,二进制附件);与 `body` 互斥;**不可用 `@file`** |
| `encoding` | string | 否 | 传输编码(RFC 2045 §6 CTE):`none`(缺省)/`7bit`/`8bit`/`binary`/`base64`/`quoted-printable` |

`encoding` 的 `none`/`7bit`/`8bit`/`binary` 为**恒等编码**(透传,仅声明 body 字节性质、不做变换);
`base64`/`quoted-printable` 为真变换。设非 `none` 时建议配对应 `Content-Transfer-Encoding` 头。

## 序列化格式(RFC 2046 §5.1.1)

```text
--boundary\r\n
{part1 headers}\r\n
\r\n
{part1 encoded body}\r\n
--boundary\r\n
{part2 headers}\r\n
\r\n
{part2 encoded body}\r\n
--boundary--\r\n
```

- 每 part body 先取字节(`body` 或 `body_hex`),再按 `encoding` 编码:
  `base64` 按 RFC 2045 **每 76 字符折行**;`quoted-printable` 按 RFC 2045 §6.7;`none`/`7bit`/`8bit`/`binary` 原样透传。
- **不做 CRLF 归一化**:`body`(含 `@file` 注入)与 `body_hex` 均保留原始字节。`@file` 可注入二进制附件
  (图片、压缩包),归一化会破坏文件字节;换行正确性交给用户。
- HTTP 下 `auto_content_length: true` 按 multipart 实际字节长度算 CL(详见 `http_request`/`http_response`)。
- EML 下 multipart 字节即邮件正文,作用顺序固定「编码 → 拼装」;dot-stuffing 与终止符由承载的
  SMTP/POP3 在最外层自动追加(见 `pmaker://schema/eml_data`)。

## 组合规则

- `parts` 至少 1 个(空报错)。
- `boundary` 非空时符合 RFC 2046 §5.1.1(长度 1-70、bchars 字符集、空格不结尾);空则用默认值。
- 每 part:`body` 与 `body_hex` 互斥;`body_hex` 须合法 `0x` hex;`encoding` ∈ 六值枚举。
- 父层互斥(由父层校验,非本子结构):`multipart` 与 `body` 互斥、与 `raw`/`raw_hex`(EML)互斥。

## 一致性告警(软告警,非硬错)

畸形用例可能故意不一致,故只告警不阻断:

- **boundary 一致性**:父层 `Content-Type` 头的 `boundary=` 与 `multipart.boundary`(或默认值)不符 → 告警;
  父层有 `multipart` 但缺 `Content-Type` 头 → 告警。
- **CTE 一致性**:part 设 `encoding`(非 `none`)但 part 头 `Content-Transfer-Encoding` 缺失或不符 → 告警
  (`7bit`/`8bit`/`binary` 同样参与,它们是 RFC 2045 真实 CTE 标签)。
- **boundary 碰撞**(生成 pcap 时检查):part 编码后 body 里出现独占一行的 `--<boundary>` → 告警
  (RFC 2046 §5.1.1:分界符须独占一行,解析端会误判切分)。`@file` 注入附件时尤其隐蔽;命中请换更长的 boundary。

## 静默陷阱

- **`body` 不归一化换行**:YAML `|` 块标量带入裸 `\n`;协议要 CRLF 写 `"a\r\nb"`。`@file` 注入二进制附件
  也不归一化(归一化会破坏文件字节)。
- **`body_hex` 不可用 `@file`**:hex 字段注入原始字节会破坏 hex 语义;二进制附件用 `body` + `@file`。
- **`encoding` 恒等四态不变换**:`none`/`7bit`/`8bit`/`binary` 行为完全一致(原样透传),只声明 body 字节性质。
  以为设了 `8bit` 会做什么处理是误解。
- **boundary 碰撞只告警不拦**:part body 里独占一行的 `--<boundary>` 会让解析端误切分,但包照出
  (默认 boundary 碰撞概率极低;自定义短 boundary 易踩)。
- **HTTP `auto_content_length` 是 CL 唯一入口**:头里写 `Content-Length` 不会触发自动计算,须显式
  `auto_content_length: true`(原位覆盖占位值或末尾追加)。

## v1 限制(走父层原始字节兜底)

- **不支持嵌套 multipart**(`multipart/mixed` 内嵌 `multipart/alternative`):走父层 `raw`/`raw_hex`(EML)
  或 `payload`/`payload_hex`(HTTP)手拼。
- **不支持 preamble / epilogue**(RFC 2046:首 boundary 前、尾 boundary 后的可选文本):需加时走 `raw` 手拼。
- 缺终止符、非标换行等成帧畸形统一走 `raw`/`raw_hex`/`payload_hex`。

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `multipart.parts 至少需要 1 个 part` | 至少给 1 个 part。空 multipart / 缺终止符等畸形走父层 `raw`/`raw_hex` 或 `payload`/`payload_hex` |
| `multipart.boundary 长度须 1-70` | boundary 限 1-70 字符。非标 boundary 走父层 `raw`/`raw_hex` 或 `payload`/`payload_hex` 手拼 |
| `multipart.boundary "bad;b" 含非法字符` | bchars 限 `0-9A-Za-z'()+_,.-/:=?` 与空格(空格不结尾)。非标 boundary 走父层原始字节兜底 |
| `body 与 body_hex 只能配置一个` | part 体二选一;二进制附件用 `body`+`@file` 或 `body_hex` |
| `encoding 只能是 none/7bit/8bit/binary/base64/quoted-printable` | encoding 六值之一。非标 CTE 走父层 `raw`/`raw_hex` 或 `payload`/`payload_hex` |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 80, flags: [PSH, ACK] }
      - http_request:
          headers: { Content-Type: "multipart/mixed; boundary=b" }
          multipart: { boundary: "b", parts: [] }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 80, flags: [PSH, ACK] }
      - http_request:
          headers: { Content-Type: "multipart/mixed; boundary=b" }
          multipart:
            boundary: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            parts: [{ body: "x" }]
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 80, flags: [PSH, ACK] }
      - http_request:
          headers: { Content-Type: "multipart/mixed; boundary=bad;b" }
          multipart: { boundary: "bad;b", parts: [{ body: "x" }] }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 80, flags: [PSH, ACK] }
      - http_request:
          headers: { Content-Type: "multipart/mixed; boundary=b" }
          multipart:
            boundary: "b"
            parts:
              - body: "x"
                body_hex: "0x41"
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 80, flags: [PSH, ACK] }
      - http_request:
          headers: { Content-Type: "multipart/mixed; boundary=b" }
          multipart:
            boundary: "b"
            parts:
              - body: "x"
                encoding: uuencode
```

## 相关

`pmaker://schema/http_request`、`pmaker://schema/http_response`、`pmaker://schema/eml_data`、`pmaker://examples`
