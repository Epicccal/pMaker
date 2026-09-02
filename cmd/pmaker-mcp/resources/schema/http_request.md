# http_request —— HTTP 请求(L7,走 tcp)

一条请求 = 一个 `http_request` 层,序列化为 TCP payload `METHOD URL VERSION\r\n` + headers + `\r\n` + body。
通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
flows:
  - name: http-get
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - http_request:
              method: GET
              url: /index.html
              version: HTTP/1.1
              headers:
                Host: example.com
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `method` | string | 否 | 缺省 `GET`;空值合法 |
| `url` | string | 否 | 请求路径,缺省 `/`;空值合法 |
| `version` | string | 否 | 缺省 `HTTP/1.1`;非空须符合 `HTTP/x.y` 文法,否则报错并引导 `payload`/`payload_hex` |
| `headers` | map | 否 | 头部,保留声明顺序、支持重复头(如多个 `Cookie`);头是自由文本,**不驱动成帧/编码** |
| `body` | string | 否 | 请求体;可用 `@file(...)` 注入;与 `multipart` 互斥;**不归一化换行** |
| `multipart` | 子结构 | 否 | MIME multipart body(RFC 2046);与 `body` 互斥;详见 `pmaker://schema/multipart` |
| `auto_content_length` | bool | 否 | `true`=回填/覆盖 `Content-Length` 头值;**与 `transfer_encoding` 非空互斥(硬错)** |
| `content_encoding` | 标量 / 序列 | 否 | 表示层编码,按序应用(CE fold);元素 ∈ `gzip`/`deflate`/`deflate_raw`/`br`/`zstd`/`compress` |
| `transfer_encoding` | 标量 / 序列 | 否 | 传输层编码/成帧,按序应用(TE fold);元素 ∈ `chunked`/`gzip`/`deflate`/`deflate_raw`/`compress` |
| `chunked` | object | 否 | chunked 成帧参数,仅 TE 含 `chunked` 时有效;`size`:0=整段一块,>0=切分 |

## 作用顺序

固定三步:**body 生产(字面 / `multipart`)→ `content_encoding`(CE fold)→ `transfer_encoding`(TE 成帧)**。
`auto_content_length` 算的是 CE 之后、TE 成帧**之前**的长度,原位覆盖占位 `Content-Length` 头值(缺则末尾追加)。
`[A,B]` = `B(A(body))`(列表顺序 = fold 顺序)。

**编码 / 成帧由外置参数驱动,头部不驱动** —— 这是核心立场。合规 chunked / gzip 是一等公民走外置开关;
走私(CLA.TE / TE.CL)、evasion 靠「关掉外置开关 + 头里自由手写」构造,不为每种畸形单独加 opt-out。

## 组合规则

- `version` 非空时须 `HTTP/x.y` 文法(大小写敏感,`HTTP` 大写;`HTTP/2` 这类无 minor 写法合法);非标值报错。
- `auto_content_length: true` 且 `transfer_encoding` 非空 → **硬错**(framing 互斥,RFC 9112 §6.1)。
- `auto_content_length: true` 且 ≥2 个 `Content-Length` 头 → **硬错**(覆盖目标歧义)。
- `body` 与 `multipart` 互斥(同设硬错)。
- `chunked` 子结构仅 TE 含 `chunked` 时有效(否则硬错);`chunked.size` 不可为负、不可超 1 MiB。
- `content_encoding` 含 `chunked` → 硬错(`chunked` 是传输编码);`transfer_encoding` 含 `br`/`zstd` → 硬错(它们不是标准传输编码)。
- `method` / `url` / `version` **可含 CR/LF**(CRLF 注入 / 请求走私是受支持的畸形构造,不拦截)。

## 一致性告警(软告警,非硬错)

- `transfer_encoding` 非空但 `Transfer-Encoding` 头缺失 / 头文本与列表不符 → 疑似漏声明(或故意 evasion)。
- `content_encoding` 非空但 `Content-Encoding` 头缺失 / 头文本与列表不符 → 同上。
- `headers` 有显式 `Content-Length` 且 `transfer_encoding` 非空 → CL+TE 冲突(走私特征),不删不硬错。
- `chunked` 不在 TE 末位 / 含多个 `chunked` → 异常编码栈(IDS 绕过特征),放行。

## 静默陷阱

- **头是自由文本,不驱动成帧**:写了 `Transfer-Encoding: chunked` 头但没给 `transfer_encoding` 字段,
  body 不会分块;反之给了字段但头里写错值,只告警不拦。成帧**只认外置参数**。
- **`auto_content_length` 不理解消息语义**:它只按当前 body 字节填 CL。对 1xx / 204 / 304(不应有 body 或
  CL 语义不同)会出软告警但照填;HEAD / CONNECT 响应侧无请求方法上下文,不做任何处理(响应层同此)。
- **`body` 不归一化换行**:YAML `|` 块标量带入的是裸 `\n`;协议要 CRLF 就写 `"a\r\nb"`(双引号才解释转义)。
- **内容协商靠人/模型保证**:响应侧设了 `content_encoding` 时,请求侧 `headers` 应带 `Accept-Encoding`
  并包含该编码;工具不做跨层推断(请求层不知道响应层写了什么)。故意不协商是合法测试点,不拦不告警。
- 自动 CL 的**唯一入口**是 `auto_content_length: true`;头里的 `Content-Length` 值原样上 wire,工具不识别
  任何特殊写法(不会把 `Content-Length: 0` 当占位符)—— 占位语义只在 `auto_content_length: true` 时生效。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 请求走私(CLF 注入) | `method` / `url` / `version` 里写 `\r\n` |
| CLA.TE / TE.CL(头里手写 CL + 外置 TE) | `auto_content_length: false` + `transfer_encoding` 字段 + headers 手写 `Content-Length` |
| 非标 version / 私有方法 | `payload` / `payload_hex` |
| 异常编码栈(chunked 非末位 / 多 chunked) | `transfer_encoding: [chunked, gzip]`,出软告警,包照出 |
| 未协商的编码响应 | 省略 / 写错请求侧 `Accept-Encoding`,不拦不告警 |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `version "1.1" 非 HTTP/x.y 文法` | version 须 `HTTP/x.y`(大小写敏感)。非标 version 走 `payload` / `payload_hex` |
| `content_encoding 元素 "CHUNKED" 非法` | `chunked` 是传输编码,放进 `transfer_encoding` 不是 `content_encoding` |
| `auto_content_length 与 transfer_encoding 非空互斥` | TE 存在时不得自动 CL。走私需 TE+CL 共存时设 `auto_content_length: false` 并在 headers 手写 CL |
| `multipart 与 body 不可同设` | multipart 本身就是 body,二选一 |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 80, flags: [PSH, ACK] }
      - http_request: { version: "1.1", method: GET, url: / }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 80, flags: [PSH, ACK] }
      - http_request: { content_encoding: chunked }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 80, flags: [PSH, ACK] }
      - http_request:
          auto_content_length: true
          transfer_encoding: chunked
          body: "x"
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 80, flags: [PSH, ACK] }
      - http_request:
          body: "x"
          multipart: { boundary: "b" }
```

## 相关

`pmaker://schema/http_response`、`pmaker://schema/multipart`、`pmaker://schema/tcp_session`、`pmaker://examples`
