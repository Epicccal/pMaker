// Package writer 将构造好的数据包写入 pcap/pcapng。
//
// 使用纯 Go 的 gopacket/pcapgo,无需 libpcap、无 CGO,保证跨平台静态编译。
// 须正确设置 LinkType(含以太头用 LinkTypeEthernet,仅 L3 用 LinkTypeRaw/IPv4);
// 时间戳来自配置或由 seed 派生,不使用 time.Now()。
package writer
