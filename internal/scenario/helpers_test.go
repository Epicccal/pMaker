package scenario_test

import (
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件收录 scenario 测试包共用的辅助函数。
// ARP 的校验与告警两个测试文件共用构造助手,故集中于此。

// arpU16 取 uint16 指针,供可选字段构造。
func arpU16(v uint16) *uint16 { return &v }

// arpU8 取 uint8 指针,供可选字段构造。
func arpU8(v uint8) *uint8 { return &v }

// arpPacket 构造含指定 ARP 字段的单包场景(eth → arp)。
func arpPacket(f *scenario.ARPLayer) *scenario.Scenario {
	return &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{Stack: []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "ff:ff:ff:ff:ff:ff"}},
		{Type: "arp", Fields: f},
	}}}}
}

// baseARP 返回一个最小合法 ARP Request,由各用例按需改字段。
func baseARP() *scenario.ARPLayer {
	return &scenario.ARPLayer{
		Operation:       arpU16(1),
		SenderHWAddr:    "00:11:22:33:44:55",
		SenderProtoAddr: "192.168.1.10",
		TargetProtoAddr: "192.168.1.1",
	}
}
