// Package writer 使用 pcapgo 将已构造的数据包写入 pcap。
//
// 写出时根据场景的 link_type 设置 LinkType;每个包的时间戳由上游构造好的
// builder.OutPacket.Time 提供,writer 不自行生成时间。
package writer
