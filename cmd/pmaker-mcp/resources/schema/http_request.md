# http_request —— HTTP 请求(L7,走 tcp)

```yaml
# 合规 chunked:body 经 gzip 压缩后分块传输;framing 由 TE 接管,不得带 auto_content_length
- http_request:
    method: POST
    url: /api/vulnerable
    version: HTTP/1.1
    content_encoding: gzip
    transfer_encoding: chunked
    chunked:
      size: 8
    headers:
      Host: example.com
      Accept-Encoding: gzip, br      # 声明可接受的响应编码;响应侧用 content_encoding 时应与此协商一致
      Content-Type: application/json
      Content-Encoding: gzip
      Transfer-Encoding: chunked
    body: '{"k":"v"}'
```

```yaml
# 合规定长:body 经 gzip 压缩后由 auto_content_length 回填 Content-Length;不得同时给 transfer_encoding
- http_request:
    method: POST
    url: /api/vulnerable
    version: HTTP/1.1
    auto_content_length: true
    content_encoding: gzip
    headers:
      Host: example.com
      Content-Type: application/json
      Content-Encoding: gzip
      Content-Length: 0            # 占位值,auto_content_length: true 会原位覆盖为压缩后长度
    body: '{"k":"v"}'
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `method` | string | 否 | 缺省 GET |
| `url` | string | 否 | 请求路径 |
| `version` | string | 否 | 缺省 HTTP/1.1;非空需符合 `HTTP/x.y` 文法(如 `HTTP/1.0`/`HTTP/2`/`HTTP/3.0`),否则报错并引导 `payload`/`payload_hex` |
| `headers` | map[string]string | 否 | 头部,保留声明顺序、支持重复头。头是用户自由文本,**不驱动成帧/编码** |
| `body` | string | 否 | 请求体;可用 `@file(...)` 注入文件内容;与 `multipart` 互斥 |
| `multipart` | object | 否 | MIME multipart body(RFC 2046);`auto_content_length: true` 按其实际长度计算;与 `body` 互斥;详见 `pmaker://schema/multipart` |
| `auto_content_length` | bool | 否 | `true`=回填/覆盖 `Content-Length` 头值(存在则原位覆盖、位置不变;缺则末尾追加);`false`(缺省)=不动 Header。算的是 `content_encoding` 之后、`transfer_encoding` 成帧之前的长度。**与 `transfer_encoding` 非空互斥(硬错)** |
| `content_encoding` | 标量或序列 | 否 | 表示层编码,按列表顺序应用(RFC 9110 §8.4);标量 `gzip` 或序列 `[deflate, gzip]`(`[A,B]`=`B(A(body))`)。元素 ∈ `gzip`/`deflate`/`deflate_raw`/`br`/`compress`(大小写不敏感、前后空白裁剪)。链式/异常编码栈走此字段。`br`(Brotli,RFC 7932)仅限 `content_encoding`,不能用于 `transfer_encoding`;`compress`(UNIX compress/LZW,RFC 9110 §8.4.1.1)历史遗留编码,CE 与 TE 均合法,现代客户端支持度低,适合 evasion 测试 |
| `transfer_encoding` | 标量或序列 | 否 | 传输层编码/成帧,按列表顺序应用(RFC 9112 §6.1);标量 `chunked` 或序列 `[gzip, chunked]`。元素 ∈ `chunked`/`gzip`/`deflate`/`deflate_raw`/`compress`(大小写不敏感、前后空白裁剪)。`chunked` 应位于末位(非末位/多个 `chunked` 触发 Warning 但照常出包);`br` 不是标准传输编码,不能用于 `transfer_encoding`。**与 `auto_content_length: true` 互斥(硬错)** |
| `chunked` | object | 否 | chunked 成帧专属参数,仅 `transfer_encoding` 含 `chunked` 时有效;字段 `size`(int):0/缺省=整段一块,>0=按指定大小切分(块长自动十六进制),<0 硬错。始终追加终止块 `0\r\n\r\n` |

> headers 保留 YAML 声明顺序输出(不再按 key 字典序);支持重复头(如多个 `Cookie`)。

### 作用顺序与语义

HTTP body 经固定三步:**body 生产(字面/`multipart`)→ `content_encoding` → `transfer_encoding` 成帧**;
`auto_content_length` 算的是 `content_encoding` 之后、成帧之前的长度。
成帧不解析头、头不驱动成帧 —— 走私(CLA.TE / TE.CL)、evasion 靠「关掉外置开关 + 头里自由手写」构造,不需为每种畸形单独加 opt-out。

- **自动 CL 的唯一入口是 `auto_content_length: true`**(原位覆盖占位 `Content-Length` 头值,或末尾追加)。头里的 `Content-Length` 值原样上 wire,工具不识别任何特殊写法。
- **互斥规则依据的是 HTTP framing 语义,不是"是否可以计算出字节长度"**:任何非空 `transfer_encoding` 的存在都令发送方不得发 CL(RFC 9112 §6.1),包括 `transfer_encoding: gzip` 这类最终 wire body 定长的情形 —— TE 一旦存在,framing 语义由 TE 接管,CL 并存会令中间代理歧义。需同时有 TE 和 CL 时(走私等畸形),设 `auto_content_length: false` 并在 `headers` 手写 CL。
- **`transfer_encoding` 列表顺序 = fold 应用顺序**;`chunked` 应位于末位(RFC 9112),非末位或多个 `chunked` 触发 Warning,但工具仍按列表顺序机械 fold 产出字节,适用于 evasion 测试。

### 内容协商(编写场景时的约定,非工具行为)

RFC 9110 §12.5.3:服务器用某种内容编码回响应,前提是客户端在 `Accept-Encoding` 里声明接受该编码。
工具**不做跨层推断**(层与层互不相识,请求层不知道响应层写了什么,反之亦然),因此协商一致性由**编写场景的人/模型**保证:

- 同一场景里若响应侧设了 `content_encoding`(如 `br`/`gzip`/`deflate`),请求侧 `headers` 应带上
  `Accept-Encoding` 并包含该编码(如 `Accept-Encoding: gzip, br`),否则抓包在真实网络中不成立
  —— 未协商却收到 `Content-Encoding: br` 属于服务器行为异常。
- **故意不协商是合法测试点**:验证客户端/中间设备如何处理未协商的编码响应时,就该省略 `Accept-Encoding`
  或让它与响应编码不符。工具不拦、不告警、不补头,请求侧 `headers` 始终原样上 wire。
- `Accept-Encoding` 只是普通请求头(自由文本),**不驱动本层任何编码/成帧行为**;它不会影响
  `content_encoding` / `transfer_encoding` / `auto_content_length` 的计算。请求自身 body 的编码由
  `content_encoding` 决定,与 `Accept-Encoding` 无关。

### 校验

- `version` 非空时需符合 `HTTP/x.y` 文法(大小写敏感,`HTTP` 为大写;允许 `HTTP/2` 这类无 minor 写法);非标值(如 `1.1`、`http/1.1`、`HTTP/x.y`)报错并引导改用 `payload`/`payload_hex`。
- `method`/`url`/`version` **可含 CR/LF**:CRLF 注入(请求走私)是受支持的畸形构造场景,不拦截。需要精确字节的其他畸形(非标 version、私有方法名等)另可走 `payload`/`payload_hex`。
- `method`/`url` 空值合法(走 builder 默认 GET / `/`),不报错。
- `content_encoding` 每个元素 ∈ `gzip`/`deflate`/`deflate_raw`/`br`/`compress`(`chunked` 是传输编码,放进 `content_encoding` 报错;`br` 仅限 `content_encoding`,不能用于 `transfer_encoding`);`transfer_encoding` 每个元素 ∈ `chunked`/`gzip`/`deflate`/`deflate_raw`/`compress`(`br` 不是标准传输编码,放进 `transfer_encoding` 报错);非法元素报错并引导 `payload`/`payload_hex`。
- `auto_content_length: true` 且 `transfer_encoding` 非空 → **硬错**(framing 互斥);`auto_content_length: true` 且 `headers` 有 ≥2 个 `Content-Length` → **硬错**(覆盖目标歧义)。
- `chunked` 子结构仅在 `transfer_encoding` 含 `chunked` 时有效(否则硬错);`chunked.size` 不可为负、不可超过固定上限(1 MiB)。

### 一致性告警(非硬错)

- `transfer_encoding` 非空但 `Transfer-Encoding` 头缺失 / 头文本与列表不符 → 疑似漏声明(或故意 evasion)。
- `content_encoding` 非空但 `Content-Encoding` 头缺失 / 头文本与列表不符 → 疑似漏声明(或故意 evasion)。
- `headers` 有显式 `Content-Length` 且 `transfer_encoding` 非空 → RFC 9112 §6.1 CL+TE 冲突(走私特征);不删不硬错。
- `transfer_encoding` 中 `chunked` 不在末位 / 含多个 `chunked` → 非常规顺序 / 异常编码栈(IDS 绕过特征);放行。
