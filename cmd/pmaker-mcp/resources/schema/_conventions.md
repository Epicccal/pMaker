# pMaker 全局通则

> 写任意场景 YAML 前读一次。这里是**唯一真相源**:两态覆盖、`@file`、Hex 字段、
> 原始字节兜底、成帧总则只在本文档定义,各层文档只链接、不重述。

## 两态覆盖(checksum / length)

`checksum` 与各类长度字段(`total_length` / `header_length` / `payload_length` / `octets` …)
都是**两态**:

- **不写** → 自动计算 / 自动修正(规范包)
- **写了** → 原样落值,**关闭**该字段的自动计算(畸形包)

这是本工具的立身之本:自动修正绝不能把本应畸形的用例悄悄改成合规包。

## 原始字节兜底

结构化字段表达不了的形态(非标命令、缺成帧、任意字节序列),一律走
`payload`(文本)/ `payload_hex`(十六进制)。校验器拒绝非标值时的标准改法就是它。
详见 `pmaker://schema/payload` 与 `pmaker://schema/payload_hex`。

## `@file(<path>)`

任意 string 字段值里可写 `@file(path)`,解析阶段替换为该文件的**原始字节**(支持二进制)。
可只占字段值的一部分,可多个拼接;`@@` 转义为字面 `@`,裸 `@`(如 `user@host.com`)原样保留。
相对路径相对 server 的 workdir。

**不可用于 hex 字段**(`payload_hex` / `body_hex` / `args_hex` / `data_hex`):
注入原始字节会破坏 hex 语义。二进制内容用对应的文本字段 + `@file`。

## Hex 字段

`payload_hex` 一类字段接受 `0x` 前缀或裸十六进制,空白被忽略。

## 成帧(framing)

成帧是**传输协议的职责**,由接入层强制,内容层不暴露开关:

- SMTP DATA / POP3 RETR:自动 dot-stuffing + `<CRLF>.<CRLF>` 终止符,**无 opt-out**
- IMAP literal:长度前缀 `{n}\r\n`,**不做** dot-stuffing / 终止符

要构造「缺终止符」「缺 dot-stuffing」等成帧畸形,走 `payload` / `payload_hex`。

## 确定性

同一份 scenario → 逐字节相同的 pcap。时间戳来自 `base_time` + 显式偏移,不用当前时间。
