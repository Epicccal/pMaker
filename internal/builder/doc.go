// Package builder 将 scenario 场景模型翻译为 gopacket layers 并序列化为字节。
//
// builder 按有序层栈由外到内串接,自动推导 next-protocol / EtherType,
// 并将 TCP/UDP checksum 绑定到就近的 IP 层。checksum/fix_lengths 等畸形覆盖
// 目前在 schema 层解析,但构建时仍按规范包序列化。
package builder
