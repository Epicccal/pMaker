# CLAUDE.md

本文件为 Claude Code 在本仓库工作时的指引。**开工前必读。**

## 项目概述

**pMaker** —— 一个用 Go 编写的 **Pcap 构造工具**,通过声明式配置批量生成各类协议的数据包,
产出 `.pcap` 文件(后续可扩展 `.pcapng`)。

- **形态**:CLI 工具优先(`pmaker gen -f scenario.yaml -o out.pcap`)。当前不对外暴露库 API,一切实现放在 `internal/`。
- **场景定义**:声明式 **YAML** 配置文件驱动。非开发者也应能编写/修改场景用例。
- **底层构包**:以 `gopacket` 序列化规范包为主,保留**原始字节兜底通道**用于构造畸形包/规避流量。

### 范围与安全边界(重要)

- 本工具**只离线生成 pcap 文件**,**默认不向网络发送任何数据包**。
- 用途是**授权环境下**做流量验证(把生成的 pcap 用 tcpreplay 等回放)。
- 若将来新增实时注入(raw socket / pcap inject),必须放在**独立的、默认关闭的构建标签**后,并显式提示权限要求 —— 不要顺手把"离线构造器"变成"在线发包工具"。

## 技术栈与关键依赖

| 用途 | 选型 | 说明 |
|------|------|------|
| 语言 | **Go 1.25+** | `go.mod` 里 `go 1.25`(gopacket v1.7 要求);优先用现代标准库(`log/slog`、`errors.Join`、`slices`/`maps`) |
| 构包/分层 | **`github.com/gopacket/gopacket`** | 社区维护 fork(Google 原版已归档,**不要**用 `google/gopacket`) |
| 写 pcap | **`gopacket/pcapgo`** | **纯 Go,无需 libpcap,无 CGO**;跨平台静态编译 |
| 配置解析 | **`gopkg.in/yaml.v3`** | 只支持 YAML 格式配置文件 |
| CLI | **标准库 `flag`** + 子命令分发 | 子命令树变深再考虑引入 `cobra`,不要一上来就加依赖 |

**构建始终 `CGO_ENABLED=0`** —— 因为写 pcap 走纯 Go 的 pcapgo,无 libpcap 依赖,保证到处能静态编译。

## 目标目录结构

> 当前为新仓库,以下为**目标架构**;新增代码请遵循此布局。

```
cmd/pmaker/          # main 包:CLI 入口、flag 解析、子命令分发,尽量薄
cmd/pmaker-mcp/      # MCP server:把生成场景 YAML / 生成 pcap 能力暴露给其他大模型(mcp-go, stdio transport)
internal/
  scenario/          # YAML schema 定义、解析、校验(带字段/行号级错误信息);AbsTime / Offset / PlannedPacket 类型
  builder/           # scenario 模型 -> gopacket layers -> 字节;BuildPlanned 消费已排序的 PlannedPacket
  flow/              # 有状态流:TCP 握手、seq/ack 递推(只产 stack 包,不含时间)
  plan/              # 时间编排:packets + flows 汇流成 PlannedPacket,按 Time 排序
  writer/            # pcap 输出、LinkType(时间戳取自 builder.OutPacket.Time)
examples/            # 可直接运行的示例场景 YAML,按协议分目录:examples/<协议>/<name>.yaml
```

golden pcap 测试基准不放在仓库根,而是**就近放在测试包内**:`internal/scenario/testdata/<协议>/<name>.pcap`
(Go 测试工作目录为包目录,测试以相对路径 `testdata/...` 读取)。**不要**在仓库根再建 `testdata/`。

**不要过早创建 `pkg/`。** 目前是 CLI 工具、无外部导入方;只有出现真实的外部消费者时,才把稳定接口提升到 `pkg/`(YAGNI)。

## 当前实现状态

最小出包链路已打通:`pmaker gen -f <yaml> -o <pcap>` 可真正出包。

**已实现层(stack 模型)**:

- L2:`eth`、`vlan`(Dot1Q,支持 QinQ 多层)
- L3:`ipv4`、`ipv6`、`gre`(隧道套报文,可递归)
- L4:`tcp`、`udp`
- 控制/应用:`icmp`、`icmpv6`、`dns`、`http_request`、`http_response`、`ftp_request`、`ftp_response`、`telnet`、`smtp_request`、`smtp_response`、`pop3_request`、`pop3_response`、`eml_data`
- 兜底:`payload`、`payload_hex`(原始字节)

**已实现特性**:

- next-proto / EtherType 按层栈自动串接,可逐层显式覆盖(制造断链)。
- TCP/UDP checksum 伪首部绑定就近 IP 层(多层 IP 时绑内层)。
- ICMP echo request/reply 及错误报文(`quote` / `quote_from`)。
- DNS A/AAAA/CNAME/NS/PTR/MX/TXT/SOA/SRV。
- FTP 控制连接命令/响应(RFC 959 多行续行)。
- SMTP 信封命令/响应(RFC 5321,MAIL/RCPT 结构化信封路径)。
- POP3 命令/响应(RFC 1939,command+args 扁平;多行响应复用 `eml_data` 子结构做 dot-stuffing + 终止符;
  响应 `status` 支持 `+OK`/`-ERR` 与 RFC 1734/4954 SASL 续行挑战 `+`)。
- **MIME multipart body**(`multipart` 子结构,嵌在 `http_request`/`http_response`/`eml_data` 内,非独立层):
  结构化构造 RFC 2046 multipart(含 `multipart/form-data` 上传、`multipart/mixed` 带附件),
  每 part 支持 base64/quoted-printable 传输编码(base64 按 RFC 2045 每 76 字符折行)与
  7bit/8bit/binary 恒等编码(RFC 2045 §6 CTE,仅声明 body 字节性质、原样透传,行为同 none);
  boundary 一致性 / CTE 一致性 / boundary 碰撞告警(非硬错);v1 不支持嵌套 multipart 与 preamble/epilogue,
  需要时走既有 `raw`/`raw_hex` 兜底。
- 确定性时间戳(`base_time` + offset,不用 `time.Now()`)。
- golden pcap 逐字节比对 + gopacket 回读测试。
- **MCP server**(`cmd/pmaker-mcp`):暴露两个 MCP 工具供其他大模型调用(stdio transport,`mcp-go`):
  `generate_yaml`(校验模型自写的场景 YAML,通过则落盘到 workdir/yaml/ 归档/复现,返回带字段路径的结构化错误)、
  `generate_pcap`(校验同一份 YAML 并出包到 workdir/pcap/,同时在 workdir/yaml/ 同步归档同名场景 YAML,文件名一致仅扩展名不同)。两工具共用同一套校验逻辑(`scenario.Parse` + `Validate` +
  `Warnings`,从 YAML 文本解析,无文件路径依赖);`validate` 不再单独成工具——校验是前两个工具的内建步骤。
  另暴露 **Resources**(`pmaker://schema`、`pmaker://schema/{layer}`、`pmaker://examples`、
  `pmaker://examples/{protocol}/{name}`)把语法与示例带内喂给模型:schema 每协议一份 markdown
  (`cmd/pmaker-mcp/resources/schema/<proto>.md`,整体 embed),examples 动态扫 workdir;
  加协议只加文件、Go 代码零改动。
- **文件占位符 `@file(<path>)`**:在 `scenario.Parse` 阶段扫描全部 string 字段,把 `@file(...)`
  替换为对应文件的原始字节(支持二进制;可只占字段值的一部分,可多个拼接;`@@` 转义为字面 `@`,
  裸 `@` 原样保留)。绝对路径原样用;相对路径相对 `baseDir`(CLI 传 scenario 文件所在目录,
  MCP server 传配置的 `workdir`)。详见下文「文件占位符 @file」。

**FTP 专项**:

- 控制通道 ↔ 数据通道:用**两条独立 flow + `start_after`** 表达消息级双向交错
  (数据 `start_after: control.<150>`、226 `start_after: data`),不引入 `data_connection` 等关联字段。
  语义与实现见下文「时间编排与汇流 → 跨流 start_after 的实现」。
- 命令/响应码校验对齐 DNS 模式:`ftp_request.command` 校验已知命令表
  (RFC 959 核心 + 常见扩展,大小写不敏感);`ftp_response.code` 校验三位 100-599(首位 1-5)。
  未列入的命令、越界响应码报错,引导改用 `payload` / `payload_hex`(与全项目「非标值走原始字节兜底」一致)。
- 端口协商一致性告警覆盖 RFC 959 + RFC 2428:
  `PASV`(227 六元组)/`PORT`(六元组)/`EPSV`(229,`(|||port|)`,地址隐式为控制连接对端)/
  `EPRT`(`|netproto|addr|port|`,netproto=1 IPv4 / 2 IPv6)。
  解析失败、协商端点与数据流 dst IP:port 不一致、协商地址与控制连接角色不匹配时产出告警
  (非硬错,畸形用例可故意不一致);EPRT 地址按地址族归一化后再比对。

**TELNET 专项**:

- 一个 `telnet` 层 = 一个 TELNET 事件(IAC 命令 / subnegotiation / NVT 文本),序列化为 TCP
  payload 字节。字段对齐 `ftp_request` 的 `{command, args}` 扁平风格:`command`(WILL/WONT/DO/
  DONT/SB/GA/BRK/IP/AO/AYT/EC/EL/NOP/DM/EOR,空=纯 NVT 文本)、`option`(ECHO/SGA/TTYPE/NAWS/
  …名或数字)、`args`(文本,自动 IAC 转义 0xFF)、`args_hex`(二进制 subneg 原始字节,不转义)。
- 多事件序列靠两种既有机制(无新关键字):同一段 TCP payload 内多个 `telnet` 层(层栈重复,
  `SerializeLayers` 顺序拼接);跨 TCP 段的会话时序用 flow 的 `messages`(每条一个 telnet 层,
  与 FTP 每条 message 一个 ftp_request/response 同构)。
- IAC(0xFF)转义是 TELNET 正确性的核心(RFC 854 §2):`args` 文本中的 0xFF 自动转义为 `IAC IAC`;
  `args_hex` 不转义(刻意构造畸形/非转义流量、NAWS 二进制)。
- 命令/option 校验对齐 DNS/FTP 模式:`command` 在已知命令表内(大小写不敏感),`option` 在已知
  option 表内或十进制/0x 数字回退(私有码);未列入报错并引导 `payload` / `payload_hex`。
  二字节控制命令禁带 option/args;WILL/WONT/DO/DONT/SB 必带 option。
- TTYPE subnegotiation(RFC 1091):`args` 视作终端名,builder 自动前缀 `IS` 限定符字节
  (常见:服务器请求,客户端回 IS+名);TTYPE SEND 需用 `args_hex: "0x01"` 显式表达(无终端名)。
  NAWS(RFC 1073)写 `args_hex: "0x00500018"`(80=0x0050、24=0x0018,大端)。
- gopacket 无 TELNET layer,自己序列化为 `gopacket.Payload`(同 HTTP/FTP);不引入 gopacket
  layer、不碰 IP 层 next-proto 串接、无独立 checksum(由 TCP 构造器处理)。

**SMTP 专项(envelope-first)**:

- 一个 `smtp_request` 层 = 一条 SMTP 信封命令,一个 `smtp_response` 层 = 一条 SMTP 响应,
  均序列化为 TCP payload 字节。**信封(envelope)优先**:MAIL/RCPT 作为信封一等概念走结构化路径
  (`from`/`to` + `params`),builder 自动包 `<>`、规范 `FROM:`/`TO:` 关键字(带冒号);
  不复刻 FTP 的 `{command, args}` 扁平形态。
- 字段:命令 `verb`(EHLO/HELO/MAIL/RCPT/DATA/QUIT/RSET/NOOP/VRFY/EXPN/HELP/AUTH/STARTTLS/BDAT/
  ETRN/ATRN,空报错)、MAIL 的 `from`(`*string` 三态:nil 报错 / `""`→`<>` 退信 / `"addr"`→`<addr>`)、
  RCPT 的 `to`(裸 string,须非空)、`params`(MAIL/RCPT 扩展参数,保留声明顺序输出、支持重复键如多
  `ORCPT`;空值→裸键如 `SMTPUTF8`,非空→`KEY=VALUE`)、`args`(非 MAIL/RCPT verb 的普通参数,如 EHLO 域名 / AUTH 机制+凭证);
  响应 `code`(200-559,SMTP 无 1xx)、`message`(单行)/`lines`(多行,互斥)。
- **分派按 verb 身份**(MAIL/RCPT 结构化 vs 其余 args 普通参数),`args` **不承担兜底职责**:
  私有/非标 verb、MAIL/RCPT 的结构性畸形(缺 `<>`、非标空格、FROM/TO 关键字大小写非标、缺冒号)
  统一走 `payload`/`payload_hex` 原始字节(校验拦截未列入 verb 并引导);地址内容畸形(如 CRLF
  注入)走结构化路径即可(`from`/`to` 裸透传不转义,`<>` 框照常包裹)。verb 原样输出(不强制大写)。
- verb 参数要求按文法分级(只判有/无):EHLO/HELO/VRFY/EXPN/AUTH/BDAT/ETRN/SEND/SOML/SAML 必带 args;
  DATA/RSET/QUIT/STARTTLS/TURN 禁带;NOOP/HELP/ATRN 可选。`params` 仅 MAIL/RCPT 有效(给其他 verb 报错)。
- 响应多行续行遵循 RFC 5321 §4.2 的 `Reply-line`(每条续行带 `code-` 前缀,末行 `code[ SP textstring]`),
  由 `builder.serializeSMTPResp` 实现(逐行带 `code-` 恰好匹配 RFC 5321 文法);
  空文本行如实输出(续行空文本 RFC 5321 合规)。
- **envelope-first**:DATA 正文用独立的 `eml_data` 层结构化构造(headers + body,自动
  dot-stuffing + 终止符,见下文「EML DATA 专项」);EHLO 一致性告警、MAIL/RCPT 参数语义级校验留后续扩展。
- gopacket 无 SMTP layer,自己序列化为 `gopacket.Payload`(同 HTTP/FTP/TELNET);不引入 gopacket
  layer、不碰 IP 层 next-proto 串接、无独立 checksum(由 TCP 构造器处理)。

**POP3 专项(command+args 扁平)**:

- 一个 `pop3_request` 层 = 一条 POP3 客户端命令,一个 `pop3_response` 层 = 一条 POP3 服务器响应,
  均序列化为 TCP payload 字节。**字段对齐 `ftp_request` 的 `{command, args}` 扁平风格**:
  POP3 命令无 SMTP MAIL/RCPT 那种结构化信封,统一走 command + args,builder 输出 `COMMAND[ args]\r\n`。
- 字段:命令 `command`(RFC 1939 核心 USER/PASS/APOP/STAT/LIST/RETR/DELE/NOOP/RSET/TOP/UIDL/QUIT
  + 扩展 CAPA/STLS/AUTH;空报错)、`args`(命令参数,如 USER 邮箱名、RETR msg#、TOP 的 `msg# n`、
  APOP 的 `name digest`、AUTH 机制);响应 `status`(`+OK`/`-ERR`,大小写不敏感、原样输出)、
  `message`(单行)/`lines`(多行普通行,如 LIST/UIDL/CAPA)/`eml`(多行 RFC 5322 正文,复用 `eml_data`
  子结构,RETR/TOP)。`message` 是状态行附带文本,可与 `lines`/`eml` 组合(多行响应首行带说明文本,
  RFC 1939 §3 合法形态,如 LIST 的 `+OK 2 messages (320 octets)`、CAPA 的 `+OK Capability list follows`),
  也可单独(单行响应);`lines` 与 `eml` 互斥(多行正文二选一);三者至少其一非空。
- **命令/状态校验对齐 DNS/FTP/SMTP 模式**:`command` 在已知命令表内(大小写不敏感),`status` 为
  `+OK`/`-ERR`/`+`(大小写不敏感;`+` 是 RFC 1734/4954 SASL 续行挑战,单字符 `+` 而非 `+OK`);
  未列入的命令、非标状态指示符报错,引导改用 `payload`/`payload_hex`
  (与全项目「非标值走原始字节兜底」一致)。命令/状态原样输出(不强制大小写),保留 `user`/`+ok` 等大小写
  构造能力(RFC 1939 §3 命令大小写不敏感,是合规测试点)。args 按 `pop3ArgsRule` 校验有/无
  (required/forbidden/optional):必带 USER/PASS/APOP/RETR/DELE/TOP/AUTH,禁带 STAT/NOOP/RSET/QUIT/CAPA/STLS,
  可选 LIST/UIDL(无参=多行,有参=msg# 单行)。
- **多行响应复用 `eml_data` 子结构**:RETR/TOP 返回 RFC 5322 邮件内容,直接嵌入 `EMLDataFields` 作 `eml`
  字段(非独立层),由 POP3 接入层(`serializePOP3Resp` 的 eml 分支)取 `serializeEMLData` 纯内容后
  强制 dot-stuffing + `<CRLF>.<CRLF>` 终止符(与 SMTP DATA 同一成帧规则,由各自接入层强制)。
  `lines` 多行(LIST/UIDL/CAPA)逐行 dot-stuff + 追加终止符(复用 `dotStuff`,接入层职责)。
  `status` 行本身不参与 dot-stuff(只有 status 行之后的多行正文才 dot-stuff,与 POP3 语义一致)。
  CAPA 响应用 `lines`(能力标签不区分大小写,如 `SASL CRAM-MD5 KERBEROS_V4`、`STLS`,RFC 2449)。
- **eml 子结构校验委托**:`eml` 非空时委托 `validateEMLDataFields` 校验(模式互斥/raw_hex 等),无需在
  pop3 侧重复实现。`@file` 占位符反射遍历自动覆盖 `eml` 子结构(HeaderMap/body/raw 等 string 字段,零改动)。
- gopacket 无 POP3 layer,自己序列化为 `gopacket.Payload`(同 HTTP/FTP/TELNET/SMTP);不引入 gopacket
  layer、不碰 IP 层 next-proto 串接、无独立 checksum(由 TCP 构造器处理)。

**EML DATA 专项(协议无关 RFC 5322 内容层)**:

- 一个 `eml_data` 层 = 一封 RFC 5322 邮件内容(headers + body),序列化为 TCP payload 字节,
  与 `smtp_request`/`smtp_response` 同级。**协议无关的内容层**:RFC 5322 内容是 SMTP/POP3/IMAP 的共同核心,
  `serializeEMLData` 只产内容字节,**不含成帧**。成帧(framing)是传输协议的职责,由接入层强制,
  不在内容层暴露开关 —— SMTP DATA(RFC 5321 §4.5.2)与 POP3 RETR(RFC 1939 §3)的接入层
  (eml_data standalone 层分支 / `serializePOP3Resp` 的 eml 分支)强制 dot-stuffing +
  `<CRLF>.<CRLF>` 终止符,无 opt-out;IMAP FETCH(RFC 9051,未来)由 `imap_response` builder
  用长度前缀 `{n}\r\n` 包装纯内容字节(无 dot-stuffing/终止符),同样不操作内容层字段。
  缺 dot-stuffing / 缺终止符等成帧畸形走 `payload`/`payload_hex` 原始字节兜底
  (与全项目「非标值走原始字节」一致)。
- 两种模式(互斥,由校验保证):结构化模式(`headers` 必填 + `body` 可空,headers 保留 YAML 声明顺序输出、
  支持重复头(如多个 `Received`);头体间自动插空行;`headers` 为空 → 报错,构造无头/缺头等畸形走 `raw`);
  原始模式(`raw` 裸透传 / `raw_hex` 十六进制,不拼头体、不归一化,构造无头/非法头/缺空行/非标换行等畸形;
  成帧仍由接入层追加)。全空报错。
- headers 值裸透传不转义:值含 `\r\n`+空白 = RFC 5322 §2.2.3 folding(合规),值含 `\r\n`+非空白
  = 头注入(畸形);重复头/有序头(RFC 5322 §3.6 Received)结构化模式已支持(`HeaderMap` 保序、
  允许重复 key),无需走 `raw`。
  `body` 支持 `@file(path)` 注入;行结束符结构化模式自动归一化(裸 `\n` → `\r\n`,抹平 YAML `|` 块标量等常用写法带入的裸 `\n`),raw 模式不归一化(保留精确字节)。
- 成帧助手 `builder.ApplyDotStuffing` / `AppendDotTerminator`(导出,供接入层调用);
  序列化纯函数 `builder.serializeEMLData`(协议无关,只产内容,不放在 `smtp.go`);
  校验 `scenario.validateEMLDataFields`(模式互斥、raw/raw_hex 互斥、空内容);
  接入 `PayloadBytes`/`serializeStack`/`validateLayer`/flow message 白名单/`summaryLayerName`。
  gopacket 无 EML layer,自己序列化为 `gopacket.Payload`。

**MIME multipart 专项(RFC 2046,子结构非层)**:

- `multipart` 子结构嵌在 `http_request`/`http_response`/`eml_data` 内作 body(非独立层,不能入 `stack`),
  结构化构造 RFC 2046 multipart(含 `multipart/form-data` 上传、`multipart/mixed` 带附件)。boundary 必须与
  父层 `Content-Type` 头的 `boundary=` 一致(一致性告警覆盖);HTTP 下自动 CL 由 `auto_content_length: true` 覆盖占位 `Content-Length` 头值(multipart 实际字节长度)。
- 每 part:`headers`(`HeaderMap` 保序、可重复)+ `body`/`body_hex`(互斥,`body_hex` **不可用 `@file`**——
  hex 字段注入原始字节会破坏 hex 语义,二进制附件用 `body` + `@file`)+ `encoding`(none 缺省 /
  7bit/8bit/binary 恒等透传 / base64/quoted-printable 真变换;base64 按 RFC 2045 每 76 字符折行,确定性)。**不做 CRLF 归一化**:`@file` 可注入二进制附件,
  归一化会破坏文件字节;换行正确性交给用户(与 HTTP body 现状一致)。
- 一致性告警(`scenario.CheckMultipartConsistency`,非硬错,与 FTP 端口告警同一套 `Warnings`):
  boundary 不一致 / 缺 `Content-Type` / part `encoding` 与 `Content-Transfer-Encoding` 头不符或缺失。
  **boundary 碰撞告警**在 builder 序列化阶段(`slog.Warn`):part 编码后 body 逐行扫描,某行独占 `--<boundary>`
  → 告警(RFC 2046 §5.1.1:分界符须独占一行,解析端会误判切分);按行匹配避免行内子串误报。
- EML 下 multipart 字节作为 content,作用顺序固定「编码 → 拼装 → stuff(接入层) → terminate(接入层)」:
  `serializeEMLData` 产纯内容(编码 → 拼装),接入层(SMTP/POP3)做 stuff + terminate。dot-stuff 作用于
  编码后整段 content(boundary 行 `--` 开头不受影响;base64 字母表不含 `.` 行首不会是 `.`;`none`/QP 的 part
  body 行首 `.` 被 stuff 成 `..` 是 SMTP 传输透明性的正确形态)。multipart 字节不再经 `normalizeCRLF`。
- **v1 限制**:不支持嵌套 multipart(`multipart/mixed` 内嵌 `multipart/alternative`)与 preamble/epilogue
  (首 boundary 前、尾 boundary 后的可选文本);需要时走既有 `raw`/`raw_hex` 手拼。缺终止符等畸形统一走 `raw`/`payload_hex`。
- 序列化纯函数 `builder.serializeMultipart`(手工拼装,不引 `mime/multipart`,便于后续加畸形开关);
  校验 `scenario.validateMultipart` / `validateBoundary`(RFC 2046 §5.1.1 bchars 字符集、长度 1-70、空格不结尾);
  一致性 `scenario/multipart_consistency.go`;`@file` 反射遍历自动覆盖嵌套 part body(`file_placeholder.go` 零改动)。

**HTTP 传输/内容编码专项(RFC 9110 §8.4 / RFC 9112 §6.1)**:

- `http_request`/`http_response` 新增外置编码开关(非头部驱动):`content_encoding`(表示层)、
  `transfer_encoding`(传输层/成帧)、`auto_content_length`(自动 CL)、`chunked`(分块参数)。
  **设计立场:外部参数驱动编码/分帧,Header 是自由文本、不驱动分帧** —— 合规 chunked/gzip 是一等公民,
  走私(CLA.TE/TE.CL)、evasion 靠「关掉外置开关 + 头里自由手写」构造,不为每种畸形单独加 opt-out(对齐「畸形包必须能绕过自动修正」)。
- **固定应用顺序**:body 生产(字面/`multipart`)→ `content_encoding`(CE fold)→ CL 基准 → `transfer_encoding`(TE fold)→ 自动 CL。
  `auto_content_length` 算的是 CE 之后、成帧之前的长度。`Content-Length: auto` 哨兵**已废弃**(头里写 `auto` 现在是普通字符串,原样上 wire,不识别不告警);自动 CL 唯一入口是 `auto_content_length: true`(原位覆盖占位 `Content-Length` 头值,或末尾追加)。
- **CodingList**(`scenario/coding_list.go`):标量或序列写法(复用 HeaderMap 的 ScalarNode/SequenceNode 双分支解码),
  解码时 `TrimSpace+ToUpper` 归一化,大小写不敏感。合法 CE ∈ `gzip`/`deflate`/`deflate_raw`,合法 TE ∈ `chunked`/`gzip`/`deflate`/`deflate_raw`;
  `chunked` 是传输编码,放进 `content_encoding` 报错。链式:列表顺序 = fold 顺序(`[A,B]`=`B(A(body))`)。
- **互斥硬错**:`auto_content_length: true` 且 `transfer_encoding` 非空(framing 互斥,RFC 9112 §6.1);`auto_content_length: true` 且 ≥2 个 `Content-Length` 头(覆盖目标歧义)。`chunked` 子结构仅 `transfer_encoding` 含 `chunked` 时有效。
- **确定性 gzip**:级别 `flate.BestSpeed`、MTIME 归零、不用 `time.Now()`(逐字节可复现)。chunked 分帧:块长十六进制、终止块 `0\r\n\r\n`、空 body 仅终止块;`chunked.size` 0/缺省=整段一块、>0=切分(<0 硬错,上限 1 MiB)。
- **一致性告警**(软错,`scenario/http_consistency.go`,与 FTP 端口告警同一套 `Warnings`):CL+TE 冲突、TE/CE 头与列表不符或缺失、`chunked` 不在末位、多个 `chunked`;1xx/204 带 body、304 在 `auto_content_length: true` 时出 Warning(保留畸形构造能力)。HEAD 与 CONNECT 响应均不做特殊处理(响应层无请求方法上下文)。
- 序列化纯函数 `builder.applyContentCodings` / `applyTransferCodings` / `chunkedFrame` / `applyAutoContentLength`(`builder/http_coding.go`);
  校验 `scenario.validateHTTPCodings`(`http_fields.go`);管线入口 `serializeHTTPReq`/`Resp` 的 `httpPayload`(`builder/http.go`)。

**已实现 flow**:TCP 三次握手、seq/ack 自动推导、`segment.mss` 分段、SYN MSS option、
HTTP 请求/响应、多轮消息、`close: fin` 四次挥手、`close: rst` 对端单包中断。

**已实现时间编排**:逐消息定时(`message.offset_time` / `segment.interval`)、
跨流 `start_after`(flow 级与 message 级)、两段式事件粒度算时。详见下文「时间编排与汇流」。

**未实现 / 简化**:

- flow 的 overlap / 重传 / IP 分片未做(乱序与段间 RTT 已由 `message.offset_time` / `segment.interval` 覆盖)。
- 畸形开关 `fix_lengths` / `checksum` **解析但忽略**(build 时 `slog.Warn`),真正的畸形 / 原始字节兜底待做。
- HTTP/EML 头部与 SMTP 参数保留 YAML 声明顺序输出、支持重复键(`scenario.HeaderMap` 有序键值集合,见 `internal/scenario/header_map.go`)。

> **源码组织**:builder 与 scenario 包已按职责拆分。
>
> builder 包:
> - `builder.go`:层栈序列化入口 `BuildPlanned` + `serializeStack` 分派。
> - `dns.go`(构包)/ `dns_enum.go`(枚举映射)/ `dns_raw.go`(原始层)。
> - `http.go` / `ftp.go` / `telnet.go` / `smtp.go` / `pop3.go`(POP3 命令/响应,多行复用 eml_data) / `eml_data.go`(协议无关 RFC 5322 正文) / `multipart.go`(RFC 2046 multipart body,被 http/eml 嵌套调用) / `icmp.go` / `icmpv6.go` / `ip.go` / `l2.go` / `transport.go` / `payload.go`:各协议构造。
>
> scenario 包(详见 `doc.go`):
> - `types.go`(顶层结构体与 Hex/PayloadHex)、`time.go`(AbsTime/Offset)、`layer_fields.go`(各层 *Fields + `MultipartBody`/`MultipartPart` 子结构)、
>   `layer_decode.go`(Layer 解码分发)、`scenario.go`(Parse/Load/Validate/Warnings)、`start_after_graph.go`、
>   `ftp_command.go`、`ftp_consistency.go`、`telnet_command.go`、`smtp_command.go`(SMTP verb/响应码校验)、`pop3_command.go`(POP3 命令/状态校验)、`eml_data.go`(RFC 5322 正文校验)、`multipart.go`(RFC 2046 multipart 校验 + boundary 校验)、`multipart_consistency.go`(boundary/CTE 一致性告警)、
>   `describe.go`(包/PlannedPacket 摘要)、`file_placeholder.go`(`@file(...)` 占位符替换,反射遍历 Scenario 全部 string 字段)。
>
> 测试按「一一对应 + 公共辅助集中」组织,详见下文「测试文件命名规约」。

## 核心数据流

```
scenario.yaml
   │  scenario 层:解析 + 校验(尽早失败,报错带字段路径)
   ▼
Scenario(Packets + Flows,每个 packet = 有序 layer 栈)
   │  flow 层:把 flows 展开成 stack 包(补全握手 / seq/ack,不含时间)
   │  plan 层:packets 与 flows 汇流 -> []PlannedPacket{ Stack; Time },按 Time 稳定排序
   ▼
[]PlannedPacket(已带显式时间戳、已排序)
   │  builder 层:有序层栈(外→内)-> gopacket layers;自动串接 next-proto,可原始字节兜底
   ▼
gopacket.SerializeBuffer  ──(逐包)──▶  writer 层:pcapgo.Writer
   ▼
out.pcap
```

## 封装与隧道:任意层级栈(核心设计)

本工具必须支持**任意深度的封装嵌套**,而不是固定的 L2/L3/L4 三段式。典型场景:

- **VLAN(802.1Q)**:Ethernet → Dot1Q → IP
- **QinQ(802.1ad)**:Ethernet → Dot1Q(S-TAG)→ Dot1Q(C-TAG)→ IP —— **双层甚至多层 VLAN**
- **GRE 隧道**:IP → GRE →(内层完整报文:IP → TCP …)—— **隧道套报文,可递归**
- 未来同一套模型可扩展:MPLS、VXLAN、GTP-U、IP-in-IP、L2TP、Geneve …

因此有以下强约束:

1. **数据模型是"有序层栈",不是固定字段。** scenario 里每个 packet 是一个**从外到内的有序 layer 列表**,
   允许**同类型重复**(QinQ 两层 VLAN)和**递归嵌套**(GRE 内层再放一整个报文)。
   **禁止**把 `eth/ipv4/tcp` 写成固定槽位 —— 那样根本表达不了 QinQ/隧道。

2. **序列化顺序:最外层在前。** `gopacket.SerializeLayers(buf, opts, 最外层, …, 最内层, payload)`,
   由外到内依次传入,gopacket 内部逐层前置。builder 按层栈顺序喂进去即可。

3. **next-protocol / EtherType 串接是最易错的一环。** 每个封装层必须正确声明"下一层是什么",
   否则解析端会在某一层解析断链:
   - `Ethernet.EthernetType`:后接 VLAN → `0x8100`;QinQ 外层 S-TAG → `0x88a8`(或按解析端预期设 `0x8100`)
   - `Dot1Q.Type`:后接内层 VLAN → `0x8100`;后接 IPv4 → `0x0800`
   - `IPv4/IPv6.Protocol`:后接 GRE → `47`
   - `GRE.Protocol`:内层 IPv4 → `0x0800`;内层 Ethernet(TEB)→ `0x6558`

   builder 应能**按层栈自动推导**这些字段(默认行为),同时允许**逐层显式覆盖**
   —— 覆盖能力正是测试"设备对畸形/非标封装如何处理"的关键。

4. **QinQ 的 TPID 必须可配置。** 标准 S-TAG 是 `0x88a8`,但很多设备实现用 `0x8100` 做双层。
   验证点往往就是"设备认不认非标 TPID",所以 `tpid`/`ethertype` 要能逐层显式指定,**不能写死**。

5. **多层 IP 时,每个传输层的 checksum 绑定到"就近那层 IP"。** 内层 TCP 的
   `SetNetworkLayerForChecksum` 要指向**内层 IP**,不是外层。builder 按嵌套关系正确配对,
   否则内层 checksum 全错(除非该用例故意要错)。

6. **长度 / MTU / 分片:** 隧道叠加会增加头部开销。用于规避的分片可能发生在**外层或内层**,两处都要能构造。

## flow 场景设计(已实现基础版;后续扩展)

`flows` 不是一种新包结构,而是一个**有状态展开器**:维护 TCP 连接状态,把一段应用层脚本
展开成一串 **stack 模型的包**,再喂给现有 builder/writer。握手、四次挥手、多轮请求全部复用
同一套底座,展开器本身是唯一的新逻辑。

### TCP 状态不变式(务必遵守)

每方向各维护一个 `seq`,`ack` 由推导得到:

- `seq` 前进量 = `len(payload) + SYN(1) + FIN(1)`
- **纯 ACK 不消耗 seq**(带当前 seq,但不前进)
- 发包时 `ack` = **对端当前 seq**

握手(SYN → SYN,ACK → ACK)与四次挥手(FIN,ACK → ACK → FIN,ACK → ACK)据此推导。
`close` 可选 `fin`(四次)/ `rst`(单包)/ `none`;`open` 可选 `handshake` / `none`(已建连)。

### 多轮请求 = 更长的脚本(无需特殊逻辑)

状态在整个脚本里**持续存在**,第 N 轮的 seq/ack 从上一轮继续累加。HTTP keep-alive / 流水线
不是特例,只是 `messages` 列表更长。展开器负责在前插握手、后插挥手;每条消息在最后一段后
+1ms 插一个对端 ACK(当前硬编码,未做 delayed-ACK / 可配策略)。

### schema(canonical)

```yaml
flows:
  - name: http-keepalive
    stack:                         # flow 中 src = TCP SYN 发起方,dst = SYN 接收方
      - eth:  { src: "...", dst: "..." }
      - ipv4: { src: "10.0.0.10", dst: "10.0.0.80", ttl: 64 }
      - tcp:  { sport: 49152, dport: 80, client_isn: 1000, server_isn: 5000, mss: 1460 }
      - tcp_session: { open: handshake, close: fin } # open: handshake|none; close: fin|rst|none
    messages:                      # 有序、方向性的应用层消息
      - from: src
        stack:
          - http_request: { method: GET, url: /a }
      - from: dst
        stack:
          - http_response: { status: 200, body: "..." }
      - from: src                 # 第 2 轮
        stack:
          - http_request: { method: GET, url: /b }
      - from: dst
        stack:
          - http_response: { status: 200, body: "..." }
```

`from` 指方向(`src`/`dst`),消息体也是一个有序 `stack`;flow message 须 ≥1 个 **payload 生产层**
(`http_request` / `http_response` / `payload_hex` / `payload` 等),按声明顺序拼接(standalone packet 同此规则)。反向消息会自动反转 eth/ipv4/tcp 的 src/dst/sport/dport.

### 分段与规避

每条消息可挂 `segment:` 策略,把一条应用消息切成多个 TCP 段(seq 按字节偏移铺开):

```yaml
segment: { mss: 8, interval: "+10ms" }
#           小段    段间间隔(缺省 1ms;显式给出模拟慢速分段/RTT)
```

`mss` 为切段大小,`interval` 为各数据段间时间间隔。`order`(乱序)/ `overlap`(重叠)/
`retransmit`(重传)**尚未实现**——写入会在解析阶段被拒(未知字段校验)。流量的**重组验证**是主战场。

### 时间编排与汇流(已实现)

`internal/plan.Plan` 是 packets 与 flows 的汇流点:把 standalone packets 与各 flow 展开后的
`PlannedPacket{ Stack []Layer; Time time.Time }` 汇流成列表,按 `Time` **稳定排序**后再交
`builder.BuildPlanned` 序列化、`writer` 落盘。`flow.Expand(f, anchor)` 接收流起始锚、自管时间轴,
直接产出 `[]scenario.PlannedPacket`(已带 Time);plan 只负责汇流 + 稳定排序,不再为 flow 内部包
分配时间。时间语义为「**相对上一包 + 跨流独立**」——各 `offset_time` 的参照点因字段而异:

- **跨流独立(flow)**:每条 flow 的 `anchor=base+flow.offset_time`(无 offset 则 = base),plan 不夹紧、不读
  packet 游标、不推进它——无 offset 的多条 flow 在 `base` **并发**(模拟浏览器多连接并行);想顺序就显式
  给递增 offset。flow 内部也不再推导跨流接续。
- **相对上一包(packet)**:`packet.offset_time` 相对**上一包**(第一包相对 `base`);无 offset 则接续默认游标
  (+1ms)。即每包 = 上一包 + offset(或 +1ms),SYN 扫描等"按间隔发包"场景由此表达。
- **相对上一条消息(message)**:flow 内单游标 `msgCursor`(= 上一条消息末尾),每条消息
  `start = msgCursor + offset`(无 offset 则紧接 `msgCursor`);第一条消息的"上一条"= 握手完成后
  (`msgAnchor`)。offset>=0 天然单调、无需夹紧,慢响应自然拖慢下一条请求(正常非流水线 HTTP)。
  挥手接在 `msgCursor` 之后(传完才关)。
- 段间按 `segment.interval` 间隔(缺省 `flow.DefaultStep`=1ms);对端 ACK 是伴生控制包,用 `DefaultStep`,
  不被数据段节奏传染。未显式定时时每包 `flow.DefaultStep`(1ms)。

时间表达(由 `AbsTime` / `Offset` 两个类型分别解析,结构性保证取值合法):

- `base_time`:场景里唯一的绝对锚(`AbsTime`,仅 ISO8601,UTC);缺省=确定性 2020 基准。
  它是各时间链的起点(flow 锚、第一包/第一条消息的"上一项")。写 `+1s` 这类偏移在解析阶段即失败。
- 所有 `Offset` 字段(`packet/flow/message.offset_time`、`segment.interval`)
  **只接受非负时长**;负值在解析阶段即失败——负偏移通常意味着 `base_time` 选错了起点
  (应把 `base_time` 提前,而非用负 offset 够到零点之前)。
- `packet.offset_time`:该包相对**上一包**的时长偏移(`Offset`,如 `+1.5s`/`+500ms`/`0s`);
  该包时刻 = `上一包时刻 + offset`(第一包 = `base + offset`)。缺省则接续默认游标(+1ms)。
- `flow.offset_time`:流起始相对**流锚基准**的时长偏移,即 `anchor = 流锚基准 + flow.offset_time`。
  **流锚基准语境相关**:无 `start_after` 时为 `base_time`(缺省则 `anchor=base`,跨流独立、并发,
  不接续别的 flow / 不读 packet 游标);置 `start_after` 时为被引消息的整组完成时刻(msgCursor)。
  缺省 `offset_time`=0(紧接 `base` 或被引 msgCursor)。
- `flow.start_after`:可选,形如 `"flow名"`(该 flow 整流结束,挥手后)或 `"flow名.message_id"`
  (该消息整组完成,msgCursor),置则本 flow 锚基准 = 被引时刻,`anchor = 被引时刻 + flow.offset_time`
  (缺省 0 紧接)。用于"一个 flow 在另一个 flow / 另一个 flow 某消息完成后开始"(如 FTP 控制通道触发
  数据通道)。这是**显式跨流依赖**(opt-in),默认独立性不变;plan 多遍拓扑展开(被引 flow 先展开登记
  时刻,引用方多遍解析),循环依赖在校验阶段(`validateStartAfter` 三色 DFS)拦截。被引 message 须在该
  flow 内有唯一 `message_id`;被引 flow 须具名且唯一。被引 flow 可声明在后(拓扑序,非声明序)。
- `message.start_after`:可选,同形 `"flow名"` 或 `"flow名.message_id"`,置则该消息起点 =
  被引时刻 + `message.offset_time`(缺省 0 紧接),取代默认的"上一条消息末尾 + offset"。用于"某条
  消息在另一个 flow / 另一个 flow 某消息完成后才开始"(比 flow 级更细:不必把整条 flow 的握手都推迟,
  只让某一条消息等跨流事件)。**禁止同流自引**(流内顺序由 message 链式游标保证);被引 flow 须具名且
  唯一、被引 message 须有唯一 `message_id`,可声明在后(拓扑序)。循环检测仍是 flow 粒度:同 flow 内
  多条 message 各自 start_after 不同被引 flow,该 flow 整体视作依赖这些被引 flow(建边 = `f.Name → refFlow`)。
- `message.offset_time`:单条消息起始相对**上一条消息末尾**的时长偏移(第一条相对握手完成后 = 流锚
  `anchor`);把该消息整组(各数据段 + 对端 ACK)锚定到 `上一条末尾 + offset`。链式 delta、天然单调,
  用于多轮请求间隔(慢响应拖慢下一条)。握手固定 `DefaultStep` 不参与定时,故第一条消息的 offset 从
  握手结束算起,避免小 offset 与握手包撞时间。
- `segment.interval`:同一消息各数据段之间的时间间隔(`Offset`,如 `+10ms`);缺省 1ms,显式给出
  模拟慢速分段 / RTT。只作用于数据段;对端 ACK 用 `DefaultStep`(伴生控制包,不被数据段节奏传染)。

**默认时间策略**:未显式定时的 standalone packet 从 `base_time` 起每 1ms 一个(第一包落 `base`,后续 +1ms);
未显式定时的 flow 在 `base` 起步(并发);未显式定时的 message 紧接上一条末尾。同 `Time` 的包保持声明/合并
顺序(稳定排序),全程不用 `time.Now()`。

#### 跨流 start_after 的实现(两段式)

`plan.Plan` 采用**两段式**处理跨流 `start_after`(典型:FTP 控制通道 ↔ 数据通道的消息级双向交错,
数据 `start_after: control.150` + 控制 226 `start_after: data`):

- **阶段一(`scheduler`)按事件粒度递归 + 记忆化,只算时刻不发包**:每个 flowStart、每条 message 的
  start 与 msgCursor、每个 flowEnd 都是独立事件,各自只依赖其引用的事件;被引事件先算出、引用方后算。
  FTP 式 `control.150 → data → control.226` 在事件粒度是有向无环的(整流粒度会压成"互等对方整流先完成"
  的死锁)。
- **阶段二各 flow 拿已算好的 per-message 起始时刻表独立 `flow.Expand`**(seq/ack 状态单次展开内连续
  维护)。`flow.Expand` 的 `schedule` 参数注入 per-message 起始时刻;无跨流依赖时退化为 `resolve` 回调
  路径,行为与历史逐字节等价。
- **事件依赖图共用**:`scenario.StartAfterGraph`(`BuildStartAfterGraph`)由 `validateStartAfter` 与
  plan 算时阶段共用,避免两处重复实现图逻辑。真环(跨流消息级互引)由校验阶段三色 DFS 拦截。

> 后续若要更通用的封装 stack 反转或外层/内层分片,可在 `PlannedPacket` 之上再加
> `PlannedPacket{ Stack []Layer; Time time.Time }` 之外的中间态;当前已支持多流按显式时间戳交织。

### 约束

- **确定性**:时间戳由 `base_time` + 显式偏移(或默认 `base + 全局序号*1ms`)派生,seed 控制乱序/抖动,不用 `time.Now()`(保持 golden 可比对)。
- **封装组合**:当前 flow.stack 先支持 eth/ipv4/tcp/tcp_session;若要把整条会话套进 QinQ/GRE,后续再升级为更通用的 stack 反转。
- **UDP**:退化情形——无握手/挥手、无 seq/ack 的一串数据报(DNS、QUIC 探测)走同一抽象。
- **测试**:每个 flow 出 golden pcap;回读用 gopacket `reassembly` 重组 TCP 流,断言应用层字节与脚本一致、无空洞、握手/挥手标志序列正确。

## 领域关键约束(最容易踩坑,务必遵守)

1. **畸形包必须能绕过自动修正。** 这是流量验证工具的立身之本。
   - 规范包:`SerializeOptions{FixLengths: true, ComputeChecksums: true}`。
   - 畸形/规避包:允许**逐字段关闭** `FixLengths` / `ComputeChecksums`,并允许写入非法的 length、错误 checksum、重叠分片等。
   - 提供**原始字节注入**(如配置里的 `payload_hex`: `0x...`):当 gopacket 无法表达某种畸形时,直接落原始字节。**绝不能**因为"修正了 checksum/length"而让本应畸形的测试包变成合规包 —— 那等于悄悄废掉了这条用例。

2. **TCP/UDP checksum 依赖 IP 伪首部。** 序列化前必须
   `transportLayer.SetNetworkLayerForChecksum(ipLayer)`,否则 checksum 恒错。除非该用例**故意**要错误 checksum。

3. **输出必须确定性可复现。** 同一份 scenario + 同一 seed → **逐字节相同**的 pcap。
   - 不要用 `time.Now()`:时间戳从配置读取,或从 seed 派生。
   - 所有"随机"(随机端口、IP ID、payload 填充)都走**可配置 seed** 的 `math/rand`,禁用全局 `rand`。
   - 保证 map 遍历等顺序稳定。
   - 这是 golden-file 测试和"测试用例可归档复现"的前提。

4. **LinkType 要选对。** 含以太头 → `layers.LinkTypeEthernet`;仅 L3 → `LinkTypeRaw`/`LinkTypeIPv4`。写反了解析端解析会全错。

5. **网络字节序为大端。** gopacket 自动处理;走原始字节通道时自己保证大端。

## 常用命令

```bash
# 构建(静态、无 CGO)
CGO_ENABLED=0 go build -o bin/pmaker ./cmd/pmaker
CGO_ENABLED=0 go build -o bin/pmaker-mcp ./cmd/pmaker-mcp

# 运行:从场景生成 pcap
./bin/pmaker gen -f examples/http/get.yaml -o out.pcap

# 校验场景文件(不出包,只查 schema)
./bin/pmaker validate -f examples/http/get.yaml

# 启动 MCP server(供其他大模型调用)
./bin/pmaker-mcp -workdir .

# 测试 / 覆盖率
go test ./...
go test -race ./...
go test -cover ./...

# 重新生成 golden 基准(约定用 -update)
go test ./internal/scenario -run TestExamplesGolden -update

# 质量门禁(提交前必跑)
gofmt -l .        # 应无输出
go vet ./...
golangci-lint run # 若已安装
```

## 编码规范

- **格式化**:`gofmt` / `goimports`;命名遵循 Go 惯例(导出加注释、缩写全大写如 `TCP`/`IP`/`ID`)。
- **错误处理**:一律 `fmt.Errorf("...: %w", err)` 包装并上抛;库代码路径**不 panic**。CLI 在 `cmd/` 层统一打到 stderr 并以非零码退出。
- **配置校验尽早、报错够具体**:指出是哪个包、哪个字段、期望什么。用户大多不是开发者,错误信息就是他们的调试器。
- **日志**:用 `log/slog`;正常输出走 stdout,诊断/进度走 stderr。
- **测试**:表驱动;新协议/新字段都要有对应的 golden pcap;关键路径跑 `-race`。
- **依赖克制**:标准库能做的不引第三方;新增依赖前先问"是否真需要"(参见构包/CLI 选型说明)。

## 配置文件约定

- 只支持 YAML 格式配置文件。
- 顶层是**有序的 packet 列表**或 **flow 场景**;字段名 `snake_case`。
- **每个 packet 是一个 `stack`:从外到内的有序 layer 列表**,每个元素是单键 map(`- vlan: {…}`),
  **允许同类型重复**(QinQ 两层 VLAN)和递归嵌套(GRE 内层再放报文)。
- 封装层的 next-protocol / ethertype **默认自动推导**,可逐层用 `type` / `tpid` / `ethertype` 显式覆盖(制造断链等畸形)。
- 缺省字段走合理默认(自动 seq、自动 checksum、自动串接)。
- **文件占位符 `@file(<path>)`**:任意 string 字段里可写 `@file(path)`,`Load` 时替换为文件原始字节
  (支持二进制,可只占字段值一部分,可多个拼接;`@@`→`@`;绝对路径原样用,相对路径相对 scenario 目录)。
  被引文件需随场景归档(同 golden pcap),否则换机器不可复现。详见下文「文件占位符 @file」。
- **时间编排**:`base_time`(唯一绝对锚,`AbsTime`,仅 ISO8601 如 `2024-01-01T00:00:00Z`,缺省=确定性 2020 基准)、
  `packet.offset_time`、`flow.offset_time`、`message.offset_time`、`segment.interval`(均为 `Offset` 非负时长,
  如 `+1.5s`/`+500ms`)可选;跨流依赖用 `flow.start_after` / `message.start_after`。
  **完整时间语义(各 offset 参照点、start_after 规则)见上文「时间编排与汇流」,此处不重复**。
  按 `Time` 稳定排序后写盘;`base_time` 只能是绝对时刻(由 `AbsTime` 类型保证)。
- 畸形用例通过**显式开关**表达意图:`fix_lengths: false` / `checksum: 0xdead` / 覆盖 `type` 断链 / `payload_hex: "0x…"`.

示意(最终 schema 以 `internal/scenario` 的类型定义为准):

```yaml
# examples/tunnel/qinq_gre.yaml
link_type: ethernet
seed: 42
packets:
  # ① QinQ:双层 VLAN 承载普通 TCP
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb", ethertype: 0x88a8 }  # S-TAG TPID
      - vlan: { vid: 100, tpid: 0x8100 }   # 外层 S-TAG,下一层仍是 VLAN
      - vlan: { vid: 200 }                 # 内层 C-TAG,next 自动推导为 IPv4
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", ttl: 64 }
      - tcp:  { sport: 40000, dport: 80, flags: [SYN], seq: 1000 }

  # ② GRE 隧道:外层 IP → GRE → 内层完整报文
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - ipv4: { src: "1.1.1.1", dst: "2.2.2.2" }          # 外层,protocol 自动 = GRE(47)
      - gre:  {}                                           # protocol 自动 = 内层 ethertype
      - ipv4: { src: "192.168.1.1", dst: "192.168.1.2" }   # 内层 IP
      - tcp:  { sport: 1234, dport: 443, flags: [SYN] }

  # ③ 畸形用例:故意断链 + 错误 checksum + 原始字节
  - stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb", ethertype: 0x8100 }
      - vlan: { vid: 100, type: 0xffff }   # 显式覆盖 next-proto,制造解析断链
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2", checksum: 0xdead, fix_lengths: false }
      - payload_hex: 0xdeadbeef                # gopacket 无法表达时直接落原始字节
```

## 文件占位符 @file

任意 string 字段值里都可写 `@file(<path>)`,`scenario.Parse` 会在 YAML 解析后扫描全部 string 字段,
把占位符替换为对应文件的**原始字节**(支持二进制)。设计动机:HTTP multipart、FTP 数据通道、
未来 SMTP/POP3 等场景常需把外部文件内容拼进报文;占位符让"文件位置随意"——可只占字段值的一部分,
也可多个拼接,不必整段 body 都是文件。`scenario.Load` 即「读文件 → 调 `scenario.Parse`」,
`baseDir` 传 scenario 文件所在目录;MCP server 直接调 `scenario.Parse`,`baseDir` 传配置的 `workdir`。

- **语法**:`@file(path)`,以第一个 `)` 闭合(路径不可含 `)`)。`@@` 转义为字面 `@`;
  裸 `@`(如 `user@host.com`)原样保留,不误伤。
- **生效范围**:全部 string 字段(body、payload、header 值、ftp args、ICMP payload 等)。
  结构字段(layer.type、MAC/IP)写 `@file` 会被同样替换进而破坏生成,由用户自负。
- **路径**:绝对路径原样用;相对路径相对 **`baseDir`**(CLI = scenario 文件所在目录,MCP = `workdir`)。
- **实现**:见 `internal/scenario/file_placeholder.go`。反射遍历 `Scenario`,跳过 `yaml.Node`
  (ICMP type/code 等结构化字段),对 `map[string]string`(HTTP headers)替换值不替换键。
- **确定性**:文件内容固定 → 同 scenario 同输入 → 逐字节相同 pcap。被引文件需随场景一起归档
  (与 golden pcap 就近放 testdata 同理),否则换机器不可复现。
- **注意**:`payload_hex` 是 hex 编码字段,`@file` 注入原始字节会破坏 hex 语义;二进制内容请用 `payload`。

## 测试策略

1. **Golden pcap 比对**:`internal/scenario/testdata/<协议>/<name>.pcap` 逐字节比对(依赖确定性输出);用 `-update` 重生。
2. **回读校验**:生成的 pcap 能被 gopacket 正确解析(规范包场景)。
3. **可选集成**:若环境有 `tshark`,可用 `tshark -r out.pcap` 交叉验证协议解析(集成测试,非必需依赖)。

## 测试文件命名规约

1. **一一对应**:`xxx.go` ↔ `xxx_test.go`;不写看不出归属的 `load_test.go` / `payload_hex_test.go` 这类名字。
   已拆分的示例:`scenario/time.go` ↔ `scenario/time_test.go`、`builder/dns.go` ↔ `builder/dns_test.go`、
   `builder/dns_enum.go`(纯枚举映射,无对应测试文件时与 dns_test 共测)、`plan/plan.go` ↔ `plan/plan_test.go`。
2. **公共测试辅助单独放 `helpers_test.go`**:跨多个测试文件复用的 `genPcap` / `buildPackets` / `readPackets` /
   `mustAbs` / `mustOffset` / 栈构造器等集中在 `helpers_test.go`,不要在每个测试文件里复制。
   (若需被非 `_test` 文件引用则命名为 `testing.go`。)
3. **集成 / golden 测试可保留跨文件命名**(如 `examples_test.go`、`ftp_interleave_test.go`),
   但需在文件注释顶部写明覆盖范围。

## 新增一个协议的步骤(清单)

1. `internal/builder/` 加该协议的构造助手(优先复用 gopacket 现成 layer);新协议单独成文件(`proto.go`),与 `builder.go` 的层派发解耦。
2. `internal/scenario/` 加该协议的 schema 结构体 + 校验规则。
3. `internal/builder/` 接线:scenario 字段 → layer;暴露畸形开关(关闭 fix/checksum、raw 注入)。
   **若是封装层**,还须实现 next-proto/ethertype 的自动推导,并允许逐层显式覆盖。
4. `examples/<协议>/` 加一个规范用例 + 一个畸形用例(单职责、小而聚焦);**封装/隧道层再加一个嵌套用例(如 QinQ / GRE 套接)**。
5. **同步 MCP resources**:`cmd/pmaker-mcp/resources/schema/<proto>.md` 加该协议的字段速查(schema 目录整体 embed,加文件即生效,Go 代码零改动);`examples/<协议>/` 下的示例由 `pmaker://examples` 动态扫描 workdir 自动收录,无需额外登记。
6. 加 golden 测试并生成基准;`go test -race ./...` 通过。
7. README/示例文档同步。

> **硬约束**:新增协议、为已有协议加字段、或改动 schema 语义时,**必须同步更新对应的 MCP schema resource**
> (`cmd/pmaker-mcp/resources/schema/<proto>.md`)。MCP 客户端(其他大模型)靠这些 resource 带内学语法,
> schema 与实现脱节会让模型写出过时/无效的 YAML。该约束同样适用于新增/改动 MCP 工具与 resource 本身。
> **新增 MIME 子结构(如 `multipart`)同理**:子结构非层、不能入 `stack`,需在 `overview.md` 的「子结构」
> 小节登记,并在 `cmd/pmaker-mcp/resources/schema/<子结构>.md` 单独建档;嵌入它的层(http_request/
> http_response/eml_data)schema 也要加字段说明并链到子结构 schema,确保 MCP 客户端能从总览发现到。
