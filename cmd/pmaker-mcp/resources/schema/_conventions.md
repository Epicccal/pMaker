# pMaker 全局通则

> 写任意场景 YAML 前读一次。本文是**通则的唯一真相源**——两态覆盖、原始字节兜底、`@file`、
> Hex 字段、成帧规则只在这里定义;各层文档只链接、不重述。
> 顶层结构与层清单见 `pmaker://schema`,单层字段见 `pmaker://schema/<层名>`。

## 三级边界:硬错 / 软告警 / 静默坏包

写 YAML 时最该先建立的心智模型是「哪些错会被拦下、哪些不会」。

| 级别 | 表现 | 你该怎么办 |
|------|------|-----------|
| **硬错** | 校验器拒绝,不出包,报错带字段路径 | 照报错改;报错文案通常自带改法 |
| **软告警** | 照常出包,`warnings` 里附一条 | 若是**故意**构造畸形就忽略;否则按提示改 |
| **静默坏包** | 不拦、不告警,产出的字节与你的预期不符 | **只能靠预先知道**——各层文档的「静默陷阱」节列出了所有已知项 |

软告警之所以放行,是因为**畸形包是本工具的一等公民**:构造「协商端口与实际数据连接不一致」
「boundary 声明与实际不符」「literal 计数撒谎」正是流量验证的用途,校验器不该替你改回来。

静默坏包是本项目最需要警惕的一类。全局性的一条见下方「单段字节上限」,
其余按层分布,写某层前请读该层文档的「静默陷阱」节。

## 单段字节上限(写大 body 时必读)

一条 message / 一个 packet 的全部字节默认作为**单个 TCP 段**发出:不写 `segment.mss` 就不切段,
`tcp.mss` 也不会代劳(它只是 SYN 通告值,见 `pmaker://schema/tcp`)。

而单个包受 IP 长度字段约束(uint16,上限 65535):**超出时 `total_length` / `payload_length`
会静默回绕成错误值**,不报错、包体不截断,产出的是解析端会当场读歪的包。

因此 body 可能较大时——**尤其是用 `@file(...)` 注入外部文件**——必须显式写 `segment.mss` 切段,
取值通常与本 flow `tcp.mss` 的通告值一致(`segment: { mss: 1460 }`)。几百字节的小 body 无需写。

## 两态覆盖(checksum / length)

`checksum` 与各类长度字段都是**两态**:

- **不写** → 自动计算 / 自动修正(规范包)
- **写了** → 原样落值,**关闭**该字段的自动计算(畸形包)

这是本工具的立身之本:自动修正绝不能把本应畸形的用例悄悄改成合规包。

覆盖范围:checksum 见 `ipv4`/`tcp`/`udp`/`icmp`/`icmpv6`;length 见 `ipv4`(`total_length` /
`header_length`)、`ipv6`(`payload_length`)、`tcp`(`header_length`)、`udp`(`total_length`)。
16 位字段上限 `0xFFFF`;4 位的 `header_length` 取值 0-15(5-15 是规范头长范围,0-4 是合法畸形值)。
`icmp`/`icmpv6`/`vlan`/`gre`/`eth` **不开放**长度字段(gopacket 这几层不读 `FixLengths`,
开了也是空接线)。同族语义还有 `imap_*.literal.octets`(见 `pmaker://schema/imap_request`)。

**两态覆盖只在 `packets` 里可用**,flow 展开出的包不支持;要构造带错误 checksum/长度的会话包,
把该包单独写成 standalone packet。

## next-proto / EtherType 自动串接

按层栈自动推导下一层标识(`eth.ethertype` → `vlan.tpid`/`type` → `ipv4.protocol` → …),
TCP/UDP 的 checksum 伪首部自动绑定**就近**的 IP 层(多层 IP 时绑内层)。

逐层显式写 `type` / `tpid` / `ethertype` 即覆盖推导值,用来制造**解析断链**。
断链是合法构造,不产生任何告警。

## 原始字节兜底

结构化字段表达不了的形态(非标命令、非标状态码、缺成帧、任意字节序列),一律走
`payload`(文本)/ `payload_hex`(十六进制)。校验器拒绝非标值时给出的标准改法就是它。
详见 `pmaker://schema/payload` 与 `pmaker://schema/payload_hex`。

兜底层不参与 next-proto 串接、checksum、长度自动计算——落什么字节就是什么字节。

## `@file(<path>)`

任意 string 字段值里可写 `@file(path)`,解析阶段替换为该文件的**原始字节**(支持二进制)。
可只占字段值的一部分,也可多个拼接;`@@` 转义为字面 `@`,裸 `@`(如 `user@host.com`)原样保留。
相对路径相对 MCP server 的 workdir。

**不可用于 hex 字段**(`payload_hex` / `body_hex` / `data_hex`):注入原始字节会破坏 hex 语义,
且必然报「需要 0x 前缀」。二进制内容请用对应的文本字段 + `@file`(如 `payload` / `body`)。

被引文件需随场景一起归档,否则换机器不可复现。用 `@file` 注入大文件时务必回看「单段字节上限」。

## Hex 字段

`ethertype` / `tpid` / `type` / `checksum` / 各长度字段接受十进制或 `0x88a8` 形式。
`payload_hex` 一类**必须**带 `0x` 前缀。

## 换行:哪里归一化,哪里不

| 位置 | 行为 |
|------|------|
| `eml_data` 结构化模式(`headers` + `body`) | 裸 `\n` 自动归一化为 `\r\n` |
| `eml_data` 的 `raw` / `raw_hex` | **不归一化**(保留精确字节,用于构造非标换行) |
| `http_*` 的 `body`、`payload`、`multipart` 各 part 的 body | **不归一化** |

对不归一化的位置,YAML 的 `|` 块标量会带入裸 `\n`——若协议要求 CRLF,请写 `"a\r\nb"`
(双引号字符串才解释转义)。这属于静默坏包:不报错、不告警。

## 成帧(framing)

成帧是**传输协议的职责**,由接入层强制,内容层不暴露开关:

| 协议 | 成帧 |
|------|------|
| SMTP DATA(`eml_data` 独立层) | 自动 dot-stuffing + `<CRLF>.<CRLF>` 终止符,**无 opt-out** |
| POP3 多行响应(`pop3_response.lines` / `.eml`) | 同上 |
| IMAP literal(`imap_*.literal`) | 长度前缀 `{n}\r\n`,**不做** dot-stuffing / 终止符 |

要构造「缺终止符」「缺 dot-stuffing」「计数与实际不符之外的成帧畸形」,走 `payload` / `payload_hex`。

## 确定性

同一份 scenario(+ 同 `seed`)→ 逐字节相同的 pcap。时间戳来自 `base_time` + 显式偏移,
全程不用当前时间;压缩、boundary、随机填充都走确定性路径。这是 golden 比对与用例归档复现的前提。
