# imap_request —— IMAP 客户端命令(L7,走 tcp,IMAP4rev2 RFC 9051)

一条客户端输入 = 一个 `imap_request` 层,序列化为 TCP payload。IMAP 是「行 + 长度前缀混合定界」
(RFC 9051 §2.2):literal 嵌在命令中间,前后都有文本。通则见 `pmaker://schema/_conventions`。

## 骨架

```yaml
link_type: ethernet
flows:
  - name: imap-login
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.143", ttl: 64 }
      - tcp:  { sport: 49152, dport: 143, client_isn: 1000, server_isn: 5000 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - imap_request: { tag: A001, command: LOGIN, args: "alice secret" }
      - from: dst
        stack:
          - imap_response: { tag: A001, status: OK, text: "LOGIN completed" }
```

## 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `tag` | string | 形式 A 必填 | 1*<ASTRING-CHAR except `+`>;`+` 被排除(与 continuation 歧义);`]` 合法;大小写敏感 |
| `command` | string | 形式 A 必填 | 已知命令表(大小写不敏感、原样输出);非标走 `payload`/`payload_hex` |
| `args` | string | 条件 | 命令参数,裸透传不解析;有/无按命令策略;**禁含 `\r` / `\n`** |
| `line` | string | 形式 B | 裸行(DONE / SASL base64 续行 / 取消 literal 的 `*`);与 tag/command/args 互斥;**禁含 `\r` / `\n`** |
| `literal` | `IMAPLiteral` 子结构 | 条件 | 长度前缀八位组,可附在命令行末尾或作形式 C 独立消息;见下方 |

## 三形式(互斥,由字段组合决定)

- **形式 A 命令行**:`tag` + `command`(+ `args` + `literal`)→ `tag SP command[ SP args][ SP literal]\r\n`。
- **形式 B 裸行**:仅 `line`(如 IDLE 退出 `DONE`)→ `line\r\n`。
- **形式 C 八位组**:`literal.emit: data` → 仅 literal 数据 + `\r\n`(同步 literal 第③段)。

`literal.emit` 三态:`full`(缺省,`{n}\r\n`+数据)/ `prefix`(仅 `{n}\r\n`,第①段)/ `data`(仅数据+`\r\n`,第③段)。
同步 literal(`{n}`,client→server)须等服务器 `+` 续行才能发数据,故一条命令拆三条 message
(① 前缀 / ② `+` 续行 / ③ 数据);非同步(`{n+}`)一次发完。

## IMAPLiteral 子结构(嵌在 `literal` 字段,非独立层)

| 字段 | 说明 |
|------|------|
| `eml` / `data` / `data_hex` | 八位组内容三选一(互斥);`eml` 复用 `eml_data` 子结构取纯内容;`data_hex` **不可用 `@file`** |
| `octets` | 两态覆盖:nil=自动算实际字节数;非 nil=原样落值(关闭自动计算,构造「计数撒谎」) |
| `sync` | 缺省 true=`{n}`;false=`{n+}` 非同步(**仅 client→server**) |
| `binary` | true=`~{n}` literal8(**仅 server→client**;`binary && !sync` 硬错) |
| `emit` | `full`(缺省)/ `prefix` / `data` |

## 组合规则

- `line` 与 `tag`/`command`/`args` 互斥(形式 B 与形式 A)。
- `literal.emit: data`(形式 C)不得带 `tag`/`command`/`args`/`line`。
- 形式 A:`tag` 经字符集校验(非空、不含 `+` 与 atom-specials)、`command` 在已知表内,
  `args` 按命令策略判有/无(required/forbidden/optional)。
- 所有文本字段(`args` / `line`)禁含 `\r` / `\n`(会注入额外命令行)。
- `literal`:内容三选一;`octets` 非 nil 须非负;`emit ∈ {full/prefix/data}`;
  `sync: false` 仅 client→server;`binary: true` 须 `sync: true`(literal8 无 `{n+}`)。

**已知命令**:CAPABILITY/LOGOUT/NOOP/LOGIN/AUTHENTICATE/STARTTLS/APPEND/CREATE/DELETE/ENABLE/
EXAMINE/LIST/NAMESPACE/RENAME/SELECT/STATUS/SUBSCRIBE/UNSUBSCRIBE/IDLE/LSUB/CLOSE/UNSELECT/
EXPUNGE/COPY/MOVE/FETCH/STORE/SEARCH/UID/CHECK(rev1 ∪ rev2 联合)。

## 一致性告警(软告警)

- `literal.octets` 显式值与实际字节数不符 → 软告警(`imap.literal-octets-mismatch`;「计数撒谎」是合法畸形,告警仅供复核,不阻断)。

## 静默陷阱

- **同步 literal 须手动拆三条 message**:写 `literal: { sync: true, ... }` + `emit: full` 会在一条
  消息里把 `{n}\r\n`+数据一次发出,**不会**等服务器 `+`。合规的同步 literal 要拆成 ① `emit: prefix`
  ② 服务器 `imap_response: { tag: "+", ... }` ③ `emit: data` 三条 message,靠 flow `messages` 排时序。
- **`literal.eml` 走 `eml_data` 纯内容,IMAP 加 `{n}\r\n` 前缀,不做 dot-stuffing / 终止符**
  (IMAP 靠长度前缀定界,与 SMTP/POP3 不同)。把 SMTP 的成帧心智搬过来会出错。
- **`octets` 计数撒谎只告警不拦**:写 `octets: 9999` 而实际 342 字节会原样落值,这是构造解析器攻击
  的正道,但笔误也同样只告警。
- **`command` 拼错是硬错**(如 `LOGN`),无数字兜底 —— 与 `dns.type` 的数字回退不同。
- **`tag` 大小写敏感**(与 command/status 不同),`A001` 与 `a001` 是不同 tag。
- **非标间距状态行**(如 `* OK[UIDVALIDITY 1]` 缺空格)不走 `data`,走 `payload` / `payload_hex` 手拼。

## 畸形构造

| 想构造 | 用 |
|--------|-----|
| 私有 / 非标命令 | `payload` / `payload_hex` |
| 非标 tag(含 `+` / atom-specials) | `payload` / `payload_hex` |
| literal 计数撒谎 | `octets: 9999`(原样落值,出软告警) |
| 非同步 literal `{n+}` | `sync: false`(仅 client→server) |
| `~{n+}`(未定义 token) | `payload_hex`(`binary && !sync` 被拦) |
| 非标间距 / 缺空格状态行 | `payload` / `payload_hex` |

## 报错 → 改法

| 报错含 | 改法 |
|--------|------|
| `需要 tag` | 形式 A 命令行 `tag` 必填。裸行走 `line`,纯八位组用 `literal.emit: data` |
| `未知 IMAP 命令` | 命令不在已知表内。私有 / 非标命令改用 `payload` / `payload_hex` |
| `tag "A+001" 含 '+',IMAP tag 不得包含 '+'` | tag 不得含 `+` 与 atom-specials(`]` 合法)。非标 tag 走 `payload` / `payload_hex` |
| `line 与 tag/command/args 互斥` | 裸行(形式 B)整行内容写在 `line` 里,不混 tag/command/args |

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.143" }
      - tcp:  { sport: 49152, dport: 143, flags: [PSH, ACK] }
      - imap_request: { command: LOGIN, args: "a b" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.143" }
      - tcp:  { sport: 49152, dport: 143, flags: [PSH, ACK] }
      - imap_request: { tag: A001, command: LOGN, args: "a b" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.143" }
      - tcp:  { sport: 49152, dport: 143, flags: [PSH, ACK] }
      - imap_request: { tag: "A+001", command: LOGIN, args: "a b" }
```

```yaml-bad
link_type: ethernet
packets:
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.143" }
      - tcp:  { sport: 49152, dport: 143, flags: [PSH, ACK] }
      - imap_request: { tag: A001, command: LOGIN, args: "a b", line: DONE }
```

## 相关

`pmaker://schema/imap_response`、`pmaker://schema/eml_data`、`pmaker://schema/_why_imap_grouping`、`pmaker://schema/tcp_session`、`pmaker://examples`
