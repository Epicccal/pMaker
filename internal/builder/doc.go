// Package builder 将 scenario 场景模型翻译为 gopacket layers 并序列化为字节。
//
// builder 按有序层栈由外到内串接,自动推导 next-protocol / EtherType,
// 并将 TCP/UDP checksum 绑定到就近的 IP 层。checksum 三态覆盖已实现:
// 不写则自动计算,显式写值则关闭自动计算、值原样上 wire(ipv4/tcp/udp/icmp/icmpv6)。
// fix_lengths 仍解析但忽略(独立一轮做)。
//
// 入口 BuildPlanned 消费 internal/plan 产出的 PlannedPacket(已带显式时间戳并排序),
// 时间戳直接取自 PlannedPacket.Time;builder 不再自行分配时间。
package builder
