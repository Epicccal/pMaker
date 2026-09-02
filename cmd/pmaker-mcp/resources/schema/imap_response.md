# imap_response —— IMAP4rev2 服务器响应(L7,走 tcp)

一条 IMAP 服务器响应 = 一个 `imap_response` 层,序列化为 TCP payload 字节。IMAP4rev2
(RFC 9051)响应按 `tag` 三态 + 内容两组分流:

- **tag 三态**:`*`= untagged(服务器主动数据/状态);具体 tag(如 `a001`)= tagged(命令完成);
  `+`= continuation(同步 literal 续行请求)。
- **状态组**(`status` + `code` + `text`):`* OK [UIDVALIDITY 3857529045] UIDs valid\r\n`。
- **数据组**(`data` + `literal` + `tail`):`* 1 FETCH (BODY[] {n}\r\n<octets>)\r\n`,
  literal 嵌在括号表达式中间(前有 data 文本、后有 tail)。两组**互斥**,见下方「状态组 vs 数据组」。

状态组(tagged OK 带 code):

```yaml
- imap_response:
    tag: "a002"
    status: "OK"
    code: "CAPABILITY IMAP4rev2 IDLE MOVE"
    text: "LOGIN completed"
```

数据组(untagged FETCH,含 literal + tail):

```yaml
- imap_response:
    tag: "*"
    data: "1 FETCH (BODY[] "
    literal:
      eml:
        headers:
          From: alice@example.com
          Subject: Hello
        body: "Hi Bob,\r\nThis is a test message.\r\n"
    tail: ")"
```

continuation(同步 literal 续行,`tag: "+"`,仅 `text`):

```yaml
- imap_response:
    tag: "+"
    text: "Ready for literal data"
```

多条 untagged 响应共处一个 TCP 段(在同一个 stack 里重复写 `imap_response` 层):

```yaml
- from: dst
  stack:
    - imap_response:
        tag: "*"
        data: "FLAGS (\\Answered \\Flagged)"
    - imap_response:
        tag: "*"
        data: "42 EXISTS"
    - imap_response:
        tag: "a003"
        status: "OK"
        code: "READ-WRITE"
        text: "SELECT completed"
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `tag` | string | 是 | `*`(untagged)/ 具体命令 tag(tagged)/ `+`(continuation);具体 tag 与 `imap_request` 同一套校验:不能含 `+`、atom-specials(`( ) { SP % * " \`)与控制字符(**含 `\r` / `\n`**),`]` 放行;非法 tag 走 `payload`/`payload_hex` |
| `status` | string | 状态组必填 | `OK`/`NO`/`BAD`/`PREAUTH`/`BYE`(大小写不敏感,原样输出);**tagged 响应(具体 tag)只能 `OK`/`NO`/`BAD`**,`PREAUTH`/`BYE` 仅 untagged(`tag: "*"`)可用(RFC 9051 §9 `response-tagged = tag SP resp-cond-state`);与 `data` 互斥;非标状态走 `payload`/`payload_hex` |
| `code` | string | 否 | 响应码,输出时包 `[...]`(如 `[UIDVALIDITY 3857529045]`);**不能含 `]`**(嵌套歧义,解析端无法配对);仅状态组可用 |
| `text` | string | 否 | 状态行文本 / continuation 文本;**仅状态组(`status` 非空)或 continuation(`tag: "+"`)可用**,不得脱离 `status` 单独存在(无 `status` 时无落点,会被丢弃);**不能含 `\r` / `\n`** |
| `data` | string | 数据组必填 | untagged 数据文本(如 `FLAGS (...)`、`42 EXISTS`、`1 FETCH (BODY[] `);**仅 `tag: "*"` 可用**(tagged 响应文法上恒为状态形式,写具体 tag 是硬错);**首 token 不能是 `OK`/`NO`/`BAD`/`PREAUTH`/`BYE`**(否则与状态组歧义,走 status 组);**不能含 `\r` / `\n`** |
| `literal` | `IMAPLiteral` 子结构 | 否 | data 内嵌 literal(通常 FETCH BODY[]);字段同 `imap_request` 的 literal,但 `sync: false` 禁用(服务器只发同步 literal);详见 `pmaker://schema/imap_request` 的 IMAPLiteral 表 |
| `tail` | string | 否 | literal 之后的收尾文本(如 `)`);**不能含 `\r` / `\n`** |

## 状态组 vs 数据组

- **状态组**(`status` 非空):输出 `prefix status[ [code]][ SP text]\r\n`
  (prefix = `* ` / `+ ` / `tag+SP`)。`status` 必填,`code`/`text` 可选。continuation
  (`tag: "+"`)只能用状态组的 `text`,不能用 `status`/`code`/`data`/`literal`/`tail`。
  **tagged(具体 tag)的 `status` 只能 `OK`/`NO`/`BAD`**:`PREAUTH`(问候)与 `BYE`(连接终止)
  在 RFC 9051 §9 里属 `resp-cond-auth` / `resp-cond-bye`,只出现在 untagged 响应上。
- **数据组**(`data` 非空):输出 `prefix data[ literal][tail]\r\n`。`literal`/`tail` 可选。
  **数据组仅 `tag: "*"` 可用**——tagged 响应文法上恒为状态形式,给 `data` 配具体 tag 是硬错。
  data 的首个 token 不能是状态字(`OK`/`NO`/`BAD`/`PREAUTH`/`BYE`)—— 那种响应属于状态组。
- 两组互斥:`status` 与 `data`/`literal`/`tail` 不能同时出现;`code` 仅状态组可用。
  `text`/`code` 不得脱离 `status` 单独存在:没有 `status` 时它们无处安放,会被丢弃并产出只有 `prefix` + CRLF 的空响应(RFC 9051 §9 要求状态响应必须带状态字)。要构造这类畸形请用 `payload`/`payload_hex`。

> `code` 输出时自动包 `[]`,故值里禁含 `]`(否则解析端无法配对括号)。
> **间距畸形的状态行不要用 `data` 绕过**:例如 `* OK[UIDVALIDITY 1]UIDs valid`(状态字与
> `[` 之间缺空格),虽然塞进 `data` 也能出字节,但那样写出来的场景语义上不再是一条状态响应;
> 这类精确字节控制请用 `payload`/`payload_hex` 手拼。
> literal 的 `eml` 字段与 `eml_data` 同构,IMAP 只加 `{n}\r\n` 前缀,
> **不做 dot-stuffing、不加终止符**(IMAP 靠长度定界,与 SMTP/POP3 的点终止符不同);
> n 自动按邮件内容的实际字节数计算,写 `octets` 可让它与实际长度不符(计数撒谎)。
> 一个 TCP 段里放多条响应就重复写 `imap_response` 层,跨段时序用 flow 的 `messages`。
