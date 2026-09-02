# http_response —— HTTP 响应(L7,走 tcp)

一条响应 = 一个 `http_response` 层,序列化为 TCP payload `VERSION STATUS REASON\r\n` + headers + `\r\n` + body。
字段与 `http_request` 对称(仅请求行↔状态行不同)。通则见 `pmaker://schema/_conventions`。

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
          - http_request: { method: GET, url: /, headers: { Host: example.com } }
      - from: dst
        stack:
          - http_response:
              status: 200
              reason: OK
              auto_content_length: true
              headers: { Content-Type: text/plain }
              body: "hello\r\n"
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `version` | string | 否 | 缺省 `HTTP/1.1`;非空须 `HTTP/x.y` 文法,否则报错并引导 `payload`/`payload_hex` |
| `status` | int | 否 | 空值(0)走默认 200;非空须 100-599,越界报错 |
| `reason` | string | 否 | 状态短语,缺省 `http.StatusText(status)` |
| `headers` | map | 否 | 头部,保留声明顺序、支持重复头(如多个 `Set-Cookie`);自由文本,**不驱动成帧/编码** |
| `body` | string | 否 | 响应体;可用 `@file(...)` 注入;与 `multipart` 互斥;**不归一化换行** |
| `multipart` | 子结构 | 否 | MIME multipart body(RFC 2046);与 `body` 互斥;详见 `pmaker://schema/multipart` |
| `auto_content_length` | bool | 否 | `true`=回填/覆盖 `Content-Length` 头值;**与 `transfer_encoding` 非空互斥(硬错)** |
| `content_encoding` | 标量 / 序列 | 否 | 表示层编码,按序应用(CE fold);元素 ∈ `gzip`/`deflate`/`deflate_raw`/`br`/`zstd`/`compress` |
| `transfer_encoding` | 标量 / 序列 | 否 | 传输层编码/成帧,按序应用(TE fold);元素 ∈ `chunked`/`gzip`/`deflate`/`deflate_raw`/`compress` |
| `chunked` | object | 否 | chunked 成帧参数,仅 TE 含 `chunked` 时有效;`size`:0=整段一块,>0=切分 |

## 作用顺序

与 `http_request` 完全相同:**body 生产 → `content_encoding`(CE fold)→ `transfer_encoding`(TE 成帧)**;
`auto_content_length` 算 CE 之后、TE 成帧之前的长度。`[A,B]` = `B(A(body))`。

## 组合规则

- `version` 非空须 `HTTP/x.y` 文法;`status` 非空须 100-599(越界如 `99` / `600` 报错)。
- `auto_content_length: true` 且 `transfer_encoding` 非空 → **硬错**(framing 互斥)。
- `auto_content_length: true` 且 ≥2 个 `Content-Length` 头 → **硬错**(覆盖目标歧义)。
- `body` 与 `multipart` 互斥(同设硬错)。
- `chunked` 子结构仅 TE 含 `chunked` 时有效;`chunked.size` 不可为负、不可超 1 MiB。
- `content_encoding` 含 `chunked` → 硬错;`transfer_encoding` 含 `br`/`zstd` → 硬错。
- `version` / `reason` **可含 CR/LF**(响应拆分是受支持的畸形构造,不拦截)。

## 一致性告警(软告警,非硬错)

- TE 非空但 `Transfer-Encoding` 头缺失 / 不符;CE 非空但 `Content-Encoding` 头缺失 / 不符 → 疑似漏声明。
- `headers` 有显式 `Content-Length` 且 TE 非空 → CL+TE 冲突(走私特征),不删不硬错。
- `chunked` 不在 TE 末位 / 含多个 `chunked` → 异常编码栈,放行。
- **`status` 1xx / 204 带 body 且 `auto_content_length: true`** → 软告警(RFC 9110:1xx/204 禁止 body 与 CL)。
- **`status` 304 且 `auto_content_length: true`** → 软告警(304 的 CL 语义是 200 body 长度,非当前 wire body)。

## 静默陷阱

- **头不驱动成帧**:同 `http_request`,成帧只认外置参数;头里写 `Transfer-Encoding` 不分块。
- **`auto_content_length` 不理解消息语义**:只按当前 body 字节填 CL。1xx/204/304 出告警但照填;
  **HEAD / CONNECT 响应不做特殊处理**(响应层无请求方法上下文,一个 2xx 是否为 CONNECT 响应无从判定;
  需用户手写正确 CL 且按需写 body)。
- **`body` 不归一化换行**:YAML `|` 块标量带入裸 `\n`;协议要 CRLF 写 `"a\r\nb"`。
- **内容协商靠人/模型保证**:本层设了 `content_encoding` 时,同场景对应请求应带 `Accept-Encoding`。
  工具不做跨层推断(响应层拿不到请求层任何信息);故意不协商是合法测试点,不拦不告警。
  一致性告警只覆盖本层内部(CE 列表与本层 `Content-Encoding` 头是否相符),**不检查请求-响应协商**。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 响应拆分(CRLF 注入) | `reason` / `version` 里写 `\r\n` |
| CLA.TE / TE.CL | `auto_content_length: false` + `transfer_encoding` + headers 手写 `Content-Length` |
| 非标 status / version | `payload` / `payload_hex` |
| 1xx/204 带 body / 304 带错误 CL | `auto_content_length: true` + 对应 status,出软告警,包照出 |
| 未协商的编码响应 | 省略 / 写错请求侧 `Accept-Encoding`,不拦不告警 |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `status 99 越界(合法 100-599` | status 空值合法(默认 200);非空须 100-599。非标 status 走 `payload` / `payload_hex` |
| `version "1.1" 非 HTTP/x.y 文法` | version 须 `HTTP/x.y`。非标 version 走 `payload` / `payload_hex` |
| `auto_content_length 与 transfer_encoding 非空互斥` | TE 存在时不得自动 CL。走私设 `auto_content_length: false` 并手写 CL |
| `multipart 与 body 不可同设` | multipart 本身就是 body,二选一 |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 80, flags: [PSH, ACK] }
      - http_response: { status: 99 }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 80, flags: [PSH, ACK] }
      - http_response: { version: "1.1", status: 200 }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1, dport: 80, flags: [PSH, ACK] }
      - http_response:
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
      - http_response:
          body: "x"
          multipart: { boundary: "b" }
```

## 相关

`pmaker://schema/http_request`、`pmaker://schema/multipart`、`pmaker://schema/_why_http_framing`、`pmaker://schema/tcp_session`、`pmaker://examples`
