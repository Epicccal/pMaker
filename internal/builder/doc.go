// Package builder 将 scenario 场景模型翻译为 gopacket layers 并序列化为字节。
//
// 按有序层栈由外到内串接,自动推导 next-protocol / EtherType,并暴露畸形开关:
// 逐字段关闭 FixLengths / ComputeChecksums、写入错误 checksum、原始字节兜底。
// 多层 IP 时,每个传输层的 checksum 须绑定到就近那层 IP。
package builder
