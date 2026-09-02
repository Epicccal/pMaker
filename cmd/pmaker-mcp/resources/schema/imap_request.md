# imap_request —— IMAP4rev2 客户端命令(L7,走 tcp)

一条 IMAP 客户端命令 = 一个 `imap_request` 层,序列化为 TCP payload 字节。IMAP4rev2
(RFC 9051)命令有三种形式,由字段组合决定:

- **命令行形式(A)**:`tag` + `command`(+ `args` + `literal`),输出 `tag SP command[ SP args][ SP literal]\r\n`。
- **裸行形式(B)**:仅 `line`(如 IDLE 退出 `DONE`),输出 `line\r\n`。一等字段,不推到 `payload`。
- **literal 八位组形式(C)**:`literal.emit: data`,仅输出 literal 数据 + `\r\n`
  (同步 literal 三段式的第③段,接在服务器 `+` 续行之后)。

`tag` 原样输出(不强制大小写);`command` 校验已知命令表(大小写不敏感),未列入的命令
报错并引导 `payload`/`payload_hex`(与全项目「非标值走原始字节兜底」一致)。

命令行形式(带 args):

```yaml
- imap_request: { tag: "a001", command: "LOGIN", args: "alice secret" }
- imap_request: { tag: "a002", command: "SELECT", args: "INBOX" }
- imap_request: { tag: "a003", command: "IDLE" }   # 无 args
```

裸行形式(IDLE 退出 `DONE`,形式 B):

```yaml
- imap_request:
    line: "DONE"
```

同步 literal 三段式 APPEND(① 命令行 + 前缀 `emit: prefix`;③ 八位组 `emit: data`,
内容走 `eml` 子结构,两处写同一份内容保证字节一致):

```yaml
# ① 命令行 + literal 前缀(仅 {n}\r\n,无数据)
- imap_request:
    tag: "a003"
    command: "APPEND"
    args: 'INBOX (\Seen) "01-Jan-2024 12:00:00 +0000"'
    literal:
      emit: "prefix"
      eml:
        headers:
          From: alice@example.com
          Subject: Appended
        body: "Hello via APPEND.\r\n"
# ③ 八位组数据 + 收尾 CRLF(仅数据,接在服务器 + 续行之后)
- imap_request:
    literal:
      emit: "data"
      eml:
        headers:
          From: alice@example.com
          Subject: Appended
        body: "Hello via APPEND.\r\n"
```

非同步 literal(`{n+}`,client 一次发完命令 + 数据,无需 `+` 续行):

```yaml
- imap_request:
    tag: "a001"
    command: "APPEND"
    args: "INBOX"
    literal:
      sync: false
      data: "raw literal octets"
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `tag` | string | 形式 A 必填 | 命令标签(atom,原样输出);**不能含 `+`** 及 atom-specials(`( ) { SP % * " \`、CTL);非法 tag 走 `payload`/`payload_hex` |
| `command` | string | 形式 A 必填 | RFC 9051 已知命令(大小写不敏感,校验后原样输出);未列入走 `payload`/`payload_hex` |
| `args` | string | 视命令 | 命令参数(按命令策略要求有/无);**不能含 `\r` / `\n`** |
| `line` | string | 形式 B 必填 | 裸行内容(如 `DONE`);与 `tag`/`command`/`args`/`literal` 互斥(裸行无参数位,整行内容都写在 `line` 里,尾随垃圾等畸形亦然);**不能含 `\r` / `\n`** |
| `literal` | `IMAPLiteral` 子结构 | 否 | 命令行内嵌 literal(同步 `{n}` / 非同步 `{n+}` / 二进制 `~{n}`);详见下表 |

## IMAPLiteral 子结构(请求侧)

literal 是 IMAP 的「行 + 长度前缀」混合成帧核心(RFC 9051 §2.2):`{n}\r\n` 前缀 +
n 字节八位组,可嵌在命令/响应文本中间。client→server 同步 literal(`{n}`)须等待
服务器 `+` 续行才能发数据,故一条命令在线上拆成三条 message(① 前缀 / ② `+` 续行 /
③ 数据),用 `emit` 三态控制每段输出什么;非同步 literal(`{n+}`)client 一次发完。

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `eml` | `eml_data` 子结构 | 三选一 | RFC 5322 邮件内容(headers + body),复用 `eml_data` 子结构(纯内容字节,IMAP 加 `{n}\r\n` 前缀,**不做 dot-stuffing/终止符**);详见 `pmaker://schema/eml_data` |
| `data` | string | 三选一 | literal 文本内容(裸透传,不归一化 CRLF) |
| `data_hex` | string | 三选一 | literal 二进制内容(hex;**不可用 `@file`**,二进制走 `data` + `@file`) |
| `octets` | int(指针) | 否 | n 的**两态覆盖**:省略(nil)= 自动按实际字节数计算;显式赋值=原样落值(关闭自动计算,构造「计数撒谎」解析器攻击,校验产软告警不阻断);**≥0** |
| `sync` | bool(指针) | 否 | `true`(缺省)= 同步 literal `{n}`(须等 `+` 续行);`false`= 非同步 `{n+}`(一次发完);**服务器→客户端方向禁用 `false`**(RFC 9051 服务器只发同步 literal) |
| `binary` | bool | 否 | `true`= 二进制 literal 前缀 `~{n}`(RFC 9051 §2.2.2,允许 NUL 等任意字节);**二进制 literal 无非同步形式**(`binary: true` 且 `sync: false` → 硬错) |
| `emit` | string | 否 | 控制本层输出哪段:`full`(缺省)= `{n}\r\n` + 数据;`prefix`= 仅 `{n}\r\n`(同步 literal 第①段);`data`= 仅数据 + `\r\n`(第③段) |

> **三形式互斥**:`line` 与 `tag`/`command`/`args`/`literal` 互斥;`literal.emit: data` 与
> `tag`/`command`/`args`/`line` 互斥。**eml / data / data_hex 三选一**,全空报错。
> `octets` 的两态覆盖与本项目的 checksum/length 覆盖同一套语义:不写则自动算,写了就原样落值,
> 保证畸形包不会被自动修正掉。literal 内容走 `eml` 子结构时,n 自动按邮件内容的实际字节数计算。
> 非法 tag 字符、命令行的间距/成帧畸形(如 tag 与 command 之间缺空格、行尾非 CRLF)走
> `payload`/`payload_hex` 手拼精确字节。多事件序列不需要新关键字:同一段 TCP payload 内
> 放多个 `imap_*` 层(按声明顺序拼接);跨 TCP 段的会话时序用 flow 的 `messages`。
