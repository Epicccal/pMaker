# multipart —— MIME multipart body(子结构,非层)

`multipart` 描述一个 MIME multipart 体(RFC 2046),作 **HTTP** 或 **EML** 的 **body**。
**不是独立层**,不能单独出现在 `stack` 里;嵌在 `http_request`/`http_response`/`eml_data` 内部作为子字段。
boundary 必须与父层 `Content-Type` 头里的 `boundary=` 参数一致(一致性告警覆盖,见下文)。

## 字段

```yaml
- http_request:
    method: POST
    url: /upload
    auto_content_length: true
    headers:
      Content-Type: "multipart/form-data; boundary=----=_pMaker_0001"
      Content-Length: 0          # 占位值,auto_content_length: true 会原位覆盖为 multipart 实际长度
    multipart:
      boundary: "----=_pMaker_0001"   # 空 → 确定性默认 "----=_pMaker_0001"
      parts:
        - headers:
            Content-Disposition: 'form-data; name="field1"'
          body: "value1"
        - headers:
            Content-Disposition: 'form-data; name="file"; filename="a.txt"'
            Content-Type: text/plain
          body: "@file(assets/a.txt)"   # @file 注入文件内容(文本或二进制)
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `boundary` | string | 否 | 分界符;空 → 确定性默认 `----=_pMaker_0001`。非空须符合 RFC 2046 §5.1.1(长度 1–70、字符集 `0-9A-Za-z'()+_,.-/:=?` 与空格,空格不结尾),否则报错并引导 `raw`/`raw_hex` |
| `parts` | []Part | 是 | 至少 1 个 part;空报错 |

### part 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `headers` | map[string]string | 否 | part 头(`Content-Disposition`/`Content-Type`/`Content-Transfer-Encoding`…),保留声明顺序、支持重复头 |
| `body` | string | 否 | part 体;支持 `@file(...)` 注入文件内容(文本或二进制附件);与 `body_hex` 互斥 |
| `body_hex` | string | 否 | part 体(`0x` 前缀十六进制,二进制附件);与 `body` 互斥;**不可用 `@file`**(`@file` 注入原始字节会破坏 hex 语义,二进制附件请用 `body` + `@file` 或 `body_hex` 写死) |
| `encoding` | string | 否 | 传输编码(RFC 2045 §6 CTE):`none`(缺省)/`7bit`/`8bit`/`binary`/`base64`/`quoted-printable`。`none`/`7bit`/`8bit`/`binary` 为恒等编码(透传,仅声明 body 字节性质、不做变换);`base64`/`quoted-printable` 为真变换。设非 `none` 时建议配对应的 `Content-Transfer-Encoding` 头(一致性告警覆盖,见下文) |

## 序列化格式(RFC 2046 §5.1.1)

```
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

- `auto_content_length: true`(HTTP)按 multipart 实际字节长度计算(原位覆盖占位 `Content-Length` 头值,详见 `http_request`/`http_response` schema)。
- 每 part body 先取字节(`body` 或 `body_hex`),再按 `encoding` 编码:
  - `base64`:`encoding/base64.StdEncoding`,按 RFC 2045 **每 76 字符折行**(`\r\n` 分隔,确定性);
  - `quoted-printable`:`mime/quotedprintable`;
  - `none`/`7bit`/`8bit`/`binary`:RFC 2045 §6 恒等编码(identity),原样透传 —— 这四者仅声明 body 字节性质(7bit 限 ASCII 短行、8bit 允许高位字节、binary 任意字节流),**不做任何变换**,与 `none` 行为一致。
- **不做 CRLF 归一化**:`body`(含 `@file` 注入的文本/二进制)与 `body_hex` 均保留原始字节(对齐 HTTP body 现状)。`@file` 可注入二进制附件(图片、压缩包),归一化会破坏文件字节;换行正确性交给用户。
- EML 下 multipart 字节作为 content,`serializeEMLData` 产纯内容(编码 → 拼装),成帧(stuff + terminate)由接入层强制(见 `eml_data` schema)。

## 互斥

- `multipart` 与 `body` 互斥(multipart 本身就是 body);
- `multipart` 与 `raw`/`raw_hex`(EML)互斥;
- 每个 part 的 `body` 与 `body_hex` 互斥。

## 一致性告警(非硬错)

畸形用例可能故意构造不一致,故只告警不阻断:

- **boundary 一致性**:父层 `Content-Type` 头的 `boundary=` 参数若与 `multipart.boundary`(或默认值)不一致 → 告警;父层有 `multipart` 但缺 `Content-Type` 头 → 告警。
- **CTE 一致性**:part 设 `encoding`(非 `none`)但 part 头 `Content-Transfer-Encoding` 缺失或与之不符 → 告警。`7bit`/`8bit`/`binary` 同样参与校验(它们是 RFC 2045 的真实 CTE 标签,应与 `Content-Transfer-Encoding` 头对齐)。
- **boundary 碰撞**(build 阶段):part 编码后 body 里若出现独占一行的 `--<boundary>`(RFC 2046 §5.1.1:分界符须独占一行),解析端会误判切分 multipart → `slog.Warn`。`@file` 注入附件时尤其隐蔽;命中时请更换更长的 boundary(默认 boundary 碰撞概率极低)。

## v1 限制

- 不支持**嵌套 multipart**(如 `multipart/mixed` 内嵌 `multipart/alternative`);需要时用 `raw` 手拼。
- 不支持 **preamble / epilogue**(RFC 2046:首 boundary 前、尾 boundary 后的可选文本);空 preamble/epilogue 本身合规(可省略),需加时用 `raw` 手拼。
- 缺终止符、非标换行等畸形 multipart 统一走既有 `raw`/`raw_hex`/`payload_hex` 兜底。
