# _why_gre_no_routing —— 为什么 GRE 不开放 Routing / SRE

设计立场:`gre` 层不开放 Routing(R 位)/ SRE 链表 / `strict_source_route`(s 位),
需要带 Routing 的 GRE 头只能走 `payload_hex` 整段手拼。三层理由:

## 1. RFC 2784 已废弃 Routing

RFC 2784(替代 RFC 1701)把 R 位划进 Reserved0 bits 1-5:**非零即收端 MUST discard**
(除非实现 RFC 1701 兼容)。也就是说,今天抓到的带 Routing 的 GRE 包是收端直接丢的
畸形流量,构造它的正确通道是原始字节,不是结构化字段。

## 2. gopacket 的序列化缺陷会写坏包

`layers.GRE.SerializeTo` 在 Routing 与 Ack 同时置位时,写完 SRE 链表的 NULL 终止符后
没有推进 offset,紧接着的 Ack 把终止符覆盖掉 —— 解码端会把 Ack 的 4 字节当成一个 SRE
继续读,整包解歪。开放结构化构造等于交付静默坏包,违反本工具「静默坏包须消灭」的
基线。

## 3. schema 成本与现网出现率不成比例

SRE 链表是变长嵌套结构(每项 address + mask + offset),schema 要为它设计一套
嵌套子结构、校验与文档;而现网带 Routing 的 GRE 出现率 ≈ 0(RFC 2784 发布于 2000 年)。

## s 位为什么不单独开放

`strict_source_route`(s 位)规定的是 Routing 字段的**内容形态**(严格源路由)。
脱离 Routing 单独置位没有语义 —— 没有那个字段的位是悬空的。两者一起不开放。

## 顺带:flags 上限 15 的由来

gopacket 把 `Flags << 3` 编进 byte1,`Flags` 的第 5 位(16<<3 = 0x80)落到与 Ack
相同的 bit 上。RFC 1701 的 Flags 是 5 位(bits 8-12),但 RFC 2637 把 bit 8 征用为 A,
Flags 收缩到 bits 9-12(4 位,0-15)—— 这恰是结构化可构造的干净子集。上限卡 15
零损失:唯一被挡的 bit 8 就是 A 位,已由 `ack` 字段表达,且 1701 自己也规定该位
MUST 传零。
