# _why_http_framing —— HTTP 编码与成帧的设计立场

> 只在质疑 `http_request` / `http_response` 的编码 / 成帧规则时读。常规字段速查见那两个层文档。

## 核心立场:外置参数驱动,头部不驱动

pMaker 的 HTTP 层把编码(表示层)与成帧(传输层)做成**外置字段**
(`content_encoding` / `transfer_encoding` / `auto_content_length` / `chunked`),
而不是**从头部推断**。这是有意为之,不是疏漏:

- **合规的 chunked / gzip 是一等公民**:开了 `transfer_encoding: chunked` 就真的分块,
  开了 `content_encoding: gzip` 就真的压缩 —— 用外置开关表达规范行为,所见即所得。
- **走私(CLA.TE / TE.CL)、evasion 是另一类一等公民**:这些畸形的关键正是「头部声明与
  实际成帧不一致」。如果把成帧绑死在头部,工具会帮你把不一致**修正掉**,正好废掉这条用例。
  所以走私靠「关掉外置开关 + 头里自由手写」构造 —— 头是自由文本,工具不解释它的值。
- **不为每种畸形单独加 opt-out**:故意缺终止符、异常编码栈(chunked 非末位 / 多 chunked)、
  CL+TE 共存,都靠「外置开关 + 自由头」组合表达,不为它们各自发明一个开关。这保持字段集小,
  也让「畸形 = 正常字段的非正常组合」这条心智贯穿全工具。

`headers` 因此是**自由文本**:写了 `Transfer-Encoding: chunked` 头但没给 `transfer_encoding` 字段,
body 不会分块;反之给了字段但头里写错值,只出软告警不拦。成帧**只认外置参数**。

## 固定作用顺序

```
body 生产(字面 / multipart) → content_encoding(CE fold) → Content-Length 基准 → transfer_encoding(TE 成帧)
```

顺序固定、不可配置。`auto_content_length` 算的是 **CE 之后、TE 成帧之前**的长度 ——
这是 CL 语义上该描述的长度(编码后的实体长度,不是原始 body 长度)。
`[A, B]` = `B(A(body))`:列表顺序 = fold 顺序,与 HTTP 的「最外层编码最后应用」一致。

## 互斥硬错的两条

- `auto_content_length: true` 且 `transfer_encoding` 非空 → 硬错。
  有 Transfer-Encoding 的报文不得带 Content-Length(RFC 9112 §6.1),自动 CL 与 TE 成帧同存必然矛盾。
  走私要 TE+CL 共存时,设 `auto_content_length: false` 并在 headers **手写** `Content-Length`。
- `auto_content_length: true` 且 ≥2 个 `Content-Length` 头 → 硬错。覆盖目标歧义。

## auto_content_length 不理解消息语义

它只按当前 body 字节填 CL,**不做跨层 / 跨消息推断**:

- 1xx / 204 不应有 body(RFC 9110),304 的 CL 语义是 200 body 长度而非当前 wire body ——
  这些情况 `auto_content_length: true` 会出软告警但**照填**(保留构造能力)。
- **HEAD / CONNECT 响应不做特殊处理**:响应层拿不到请求方法上下文(一个 2xx 是否 CONNECT 响应无从判定),
  需要正确 CL 时用户手写。这不是 bug,是分层边界的必然结果。

## 内容协商靠人保证

设了 `content_encoding` 的响应,对应请求应带 `Accept-Encoding` 并包含该编码。工具**不做跨层推断**
(请求层不知道响应层写了什么),也不告警 —— 故意不协商是合法测试点。
一致性告警只覆盖**本层内部**(CE 列表与本层 `Content-Encoding` 头是否相符),不检查请求-响应协商。

## 相关

`pmaker://schema/http_request`、`pmaker://schema/http_response`、`pmaker://schema/multipart`
