// Package builder 将 scenario 场景模型翻译为 gopacket layers 并序列化为字节。
//
// builder 按有序层栈由外到内串接,自动推导 next-protocol / EtherType,
// 并将 TCP/UDP checksum 绑定到就近的 IP 层。checksum/fix_lengths 等畸形覆盖
// 目前在 schema 层解析,但构建时仍按规范包序列化。
//
// 入口 BuildPlanned 消费 internal/plan 产出的 PlannedPacket(已带显式时间戳并排序),
// 时间戳直接取自 PlannedPacket.Time;builder 不再自行分配时间。
package builder
