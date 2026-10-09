package golden_test

import (
	"bytes"
	"testing"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// 本文件覆盖 ARP 的 gopacket 回读断言:golden 逐字节比对之外,规范包须能被
// gopacket 正确解析(EtherType 0x0806、op/hw/协议地址逐字段回读一致)。
//
// 畸形长度用例特意写 hardware_length: 8 / protocol_length: 6:gopacket 的
// ARP.SerializeTo 在 FixLengths 下用 len(地址切片)反写这两个字节,故 builder 必须
// 把地址字段同步补齐 —— 否则畸形值落不到 wire,用例会退化成规范包。下方断言读的
// 正是 wire 上的字节(data[4]/data[5]),不是解码后的结构体字段。

// TestARPRequestGolden:规范 Request 回读为 op=1、EtherType 0x0806、地址逐字段一致。
func TestARPRequestGolden(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/arp/request.yaml"))
	if len(pkts) != 1 {
		t.Fatalf("应 1 包,得到 %d", len(pkts))
	}
	arp := pkts[0].Layer(layers.LayerTypeARP).(*layers.ARP)
	if arp.Operation != layers.ARPRequest {
		t.Errorf("Operation = %d,期望 %d", arp.Operation, layers.ARPRequest)
	}
	if arp.AddrType != layers.LinkTypeEthernet || arp.Protocol != layers.EthernetTypeIPv4 {
		t.Errorf("AddrType/Protocol = %v/%v,期望 Ethernet/IPv4", arp.AddrType, arp.Protocol)
	}
	if got := macOf(arp.SourceHwAddress); got != "00:0c:29:12:34:56" {
		t.Errorf("SourceHwAddress = %s,期望 00:0c:29:12:34:56", got)
	}
	if !bytes.Equal(arp.SourceProtAddress, []byte{192, 168, 1, 10}) {
		t.Errorf("SourceProtAddress = %v,期望 192.168.1.10", arp.SourceProtAddress)
	}
	if !bytes.Equal(arp.DstProtAddress, []byte{192, 168, 1, 1}) {
		t.Errorf("DstProtAddress = %v,期望 192.168.1.1", arp.DstProtAddress)
	}
	// Request 的目标 MAC 未写,须为全零
	if !bytes.Equal(arp.DstHwAddress, []byte{0, 0, 0, 0, 0, 0}) {
		t.Errorf("DstHwAddress = %x,期望全零", arp.DstHwAddress)
	}
}

// TestARPReplyGolden:Reply 回读为 op=2,目标 MAC 落到 wire。
func TestARPReplyGolden(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/arp/reply.yaml"))
	arp := pkts[0].Layer(layers.LayerTypeARP).(*layers.ARP)
	if arp.Operation != layers.ARPReply {
		t.Errorf("Operation = %d,期望 %d", arp.Operation, layers.ARPReply)
	}
	if got := macOf(arp.DstHwAddress); got != "00:0c:29:12:34:56" {
		t.Errorf("DstHwAddress = %s,期望 00:0c:29:12:34:56", got)
	}
}

// TestARPvlanGolden:VLAN 承载时 EtherType 推导为 Dot1Q,内层 ARP 仍可回读。
func TestARPvlanGolden(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/arp/vlan_arp.yaml"))
	if pkts[0].Layer(layers.LayerTypeDot1Q) == nil {
		t.Fatal("未解析出 VLAN 层")
	}
	arpL := pkts[0].Layer(layers.LayerTypeARP)
	if arpL == nil {
		t.Fatal("VLAN 内层未解析出 ARP 层")
	}
	if op := arpL.(*layers.ARP).Operation; op != layers.ARPRequest {
		t.Errorf("Operation = %d,期望 %d", op, layers.ARPRequest)
	}
}

// TestARPMalformedLengthGolden:长度覆盖必须真落到 wire。
// gopacket 解码按 data[4]/data[5] 切地址,故 wire 上是 8/6 时解析结果仍是这组值,
// 且长度不匹配会让 gopacket 的 ARP 层成为残缺层(整包 ARP 无法解析)。
func TestARPMalformedLengthGolden(t *testing.T) {
	data := generatePcap(t, "../../examples/arp/malformed_length.yaml")
	raw := firstPacketBytes(t, data)
	// 以太头 14 字节,ARP 头自偏移 14 起:字节 4/5 是 hw/proto 长度
	if got := raw[14+4]; got != 8 {
		t.Errorf("wire hardware_length = %d,期望 8(覆盖值被 gopacket 改回了?)", got)
	}
	if got := raw[14+5]; got != 6 {
		t.Errorf("wire protocol_length = %d,期望 6(覆盖值被 gopacket 改回了?)", got)
	}
	// 地址字段须同步补齐到覆盖长度,否则回读会截断或越界
	pkts := readPackets(t, data)
	arp := pkts[0].Layer(layers.LayerTypeARP).(*layers.ARP)
	if len(arp.SourceHwAddress) != 8 {
		t.Errorf("回读 SourceHwAddress 长度 = %d,期望 8(补齐未生效)", len(arp.SourceHwAddress))
	}
	if len(arp.SourceProtAddress) != 6 {
		t.Errorf("回读 SourceProtAddress 长度 = %d,期望 6(补齐未生效)", len(arp.SourceProtAddress))
	}
}

// TestARPMalformedOpcodeGolden:非法 operation 原样落 wire,不被修正。
func TestARPMalformedOpcodeGolden(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/arp/malformed_opcode.yaml"))
	arp := pkts[0].Layer(layers.LayerTypeARP).(*layers.ARP)
	if arp.Operation != 0xdead {
		t.Errorf("Operation = 0x%x,期望 0xdead", arp.Operation)
	}
}

// TestARPSpoofingGolden:欺骗场景三包;前两包是 Gratuitous ARP(GARP),
// 第三包是中毒后的正常 IP 流量,不再含 ARP 层。
func TestARPSpoofingGolden(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/arp/spoofing.yaml"))
	if len(pkts) != 3 {
		t.Fatalf("应 3 包,得到 %d", len(pkts))
	}
	for i, want := range []string{"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"} {
		arpL := pkts[i].Layer(layers.LayerTypeARP)
		if arpL == nil {
			t.Fatalf("包 %d 未解析出 ARP 层", i)
		}
		arp := arpL.(*layers.ARP)
		// 投毒包的关键:声称持有 192.168.1.1,但源 MAC 是攻击者自己的
		if got := macOf(arp.SourceHwAddress); got != want {
			t.Errorf("包 %d SourceHwAddress = %s,期望 %s", i, got, want)
		}
		if !bytes.Equal(arp.SourceProtAddress, []byte{192, 168, 1, 1}) {
			t.Errorf("包 %d SourceProtAddress = %v,期望 192.168.1.1", i, arp.SourceProtAddress)
		}
	}
	if pkts[2].Layer(layers.LayerTypeARP) != nil {
		t.Error("包 2 是中毒后的 IP 流量,不该有 ARP 层")
	}
	if pkts[2].Layer(layers.LayerTypeTCP) == nil {
		t.Error("包 2 未解析出 TCP 层")
	}
}

// TestARPGratuitousGolden:Gratuitous ARP 的 sender/target 协议地址相同。
func TestARPGratuitousGolden(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/arp/gratuitous.yaml"))
	arp := pkts[0].Layer(layers.LayerTypeARP).(*layers.ARP)
	if !bytes.Equal(arp.SourceProtAddress, arp.DstProtAddress) {
		t.Errorf("Gratuitous ARP 的 sender/target 协议地址应相同,得到 %v / %v",
			arp.SourceProtAddress, arp.DstProtAddress)
	}
}

// macOf 把 MAC 字节格式化为冒号分隔字符串(测试断言用)。
func macOf(b []byte) string {
	const hexdig = "0123456789abcdef"
	var sb []byte
	for i, x := range b {
		if i > 0 {
			sb = append(sb, ':')
		}
		sb = append(sb, hexdig[x>>4], hexdig[x&0xf])
	}
	return string(sb)
}

// firstPacketBytes 返回 pcap 中第一个包的原始帧字节(含以太头)。
func firstPacketBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	raw, _, err := r.ReadPacketData()
	if err != nil {
		t.Fatalf("读首包: %v", err)
	}
	return raw
}
