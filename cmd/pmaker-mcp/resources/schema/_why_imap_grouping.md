# _why_imap_grouping —— IMAP 响应状态组 / 数据组互斥的设计立场

> 只在质疑 `imap_response` 的字段分流规则时读。常规字段速查见 `imap_request` / `imap_response` 层文档。

## 为什么不只用一个 `data` 字段

IMAP 服务器响应有两种根本不同的形式(RFC 9051 §9):

- **状态响应**:`tag OK [code] text` —— 命令成功 / 失败的回执。tagged 响应(具体 tag)恒为此形式,
  `status` ∈ `OK`/`NO`/`BAD`;untagged(`*`)可带 `PREAUTH`/`BYE`。
- **数据响应**:`* FLAGS (...)` / `* 1 EXISTS` / `* LIST (...) ...` —— 邮箱 / 消息数据,
  可在中间嵌 literal(`{n}\r\n` + 八位组),前后都有文本。

用一个 `data` 字段表达两者,会留下一条歧义路径:`* OK [UIDVALIDITY 1] UIDs valid` 这种状态响应
首 token 是 `OK`,与「数据响应首 token 是某个数据项」无法靠文法区分 —— 模型会误把状态响应写进 `data`。
拆成 `status`+`code`+`text`(状态组)与 `data`+`literal`+`tail`(数据组)并**互斥**,是从字段层
就消除歧义:写 `status` 必然是状态响应,写 `data` 必然是数据响应。

## 五条互斥规则是一组

拆分本身不够,还要堵住所有「半边状态 + 半边数据」的误写。故有五条联动规则:

1. `status` 与 `data` 互斥(显式二选一)。
2. `data` 的首 token 不得是 `OK`/`NO`/`BAD`/`PREAUTH`/`BYE` —— 这条才真正封死「状态响应误写进 data」
   (单靠规则 1 拦不住 `data: "OK [code] text"` 这种写法)。
3. `data` 非空时 `tag` 必须 = `*` —— tagged 响应文法上恒为状态形式,数据响应必然 untagged。
4. `code`/`text` 不得与 `data` 同现;`literal`/`tail` 非空时 `data` 须非空(literal 须依附数据组)。
5. 状态组或数据组至少一组非空;`text`/`code` 不得脱离 `status` 单独存在(无 status 时在序列化层无落点,
   会被静默丢弃)。

五条缺一就有漏网:例如只留规则 1,`{ tag: A001, data: "OK done" }` 会产出 `A001 OK done`(看似 tagged 状态
响应,但绕过了 status 白名单,`PREAUTH` 也能混进 tagged)。五条一组才把歧义路径堵完。

## 为什么 tagged 只能 OK/NO/BAD

`PREAUTH` / `BYE` 在 RFC 9051 §9 里只能 untagged(`* PREAUTH` / `* BYE`)。tagged 响应文法
`response-tagged = tag SP resp-cond-state`,`resp-cond-state` 只产 `OK`/`NO`/`BAD`。
允许 `A001 PREAUTH` 会产出文法非法的字节 —— 校验器拦下比静默产出非法包更符合本工具
「结构化字段表达不了的畸形走 payload」的原则(真要造这种字节,用 `payload` / `payload_hex` 显式落)。

## tag 三态定型

`tag` 字段三态各有文法归宿,字段值即定型:

- 具体 tag(如 `A001`)= tagged 响应(走状态组,限 OK/NO/BAD)。
- `*` = untagged(状态组五值 或 数据组)。
- `+` = continuation(`+` SP (resp-text / base64) CRLF,仅 `text` 允许)。

`+` 被排除出 tag 字符集(在 `imap_request` 与 `imap_response` 的 tag 校验里都拦),是为了与
continuation 的 `+` 前缀不歧义 —— 一个写 `tag: "A+001"` 的响应既非 tagged 也非 continuation,
是文法外的孤儿,该走 `payload`。

## 非标间距状态行走兜底

`* OK[UIDVALIDITY 1] UIDs valid`(OK 与 `[` 之间缺空格)是 RFC 9051 文法外的畸形,结构化字段
表达不了(状态组的 `status`+`code`+`text` 总会产出规范间距)。这类成帧畸形统一走
`payload` / `payload_hex` 手拼 —— 与全项目「结构化字段表达不了的畸形走原始字节兜底」一致,
不为每种间距畸形单独加开关。

## 相关

`pmaker://schema/imap_request`、`pmaker://schema/imap_response`、`pmaker://schema/eml_data`
