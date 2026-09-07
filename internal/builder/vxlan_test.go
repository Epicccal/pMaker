package builder_test

import (
	"bytes"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 VXLAN 构造:8 字节头逐字节落值、VNI/valid_id_flag 映射、
// 内外层 checksum 就近绑定、内层 VLAN 串接。
// 端到端 golden 与多包场景回读在 internal/golden/vxlan_test.go。

func vxlanScenario(vni uint32, validID *bool, dport uint16, extra ...scenario.Layer) *scenario.Scenario {
	stack := []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.20"}},
		{Type: "udp", Fields: &scenario.UDPFields{SPort: 49152, DPort: dport}},
		{Type: "vxlan", Fields: &scenario.VXLANFields{VNI: vni, ValidIDFlag: validID}},
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:22:33:44:55:66", Dst: "00:33:44:55:66:77"}},
	}
	stack = append(stack, extra...)
	return &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{Stack: stack}}}
}

// TestBuildVXLANHeaderBytes:VXLAN 头 8 字节逐字节断言 —— flag 位 + 保留 3 字节 + VNI。
func TestBuildVXLANHeaderBytes(t *testing.T) {
	valid := true
	extra := []scenario.Layer{
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.10", Dst: "192.168.1.20"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 40000, DPort: 80, Flags: []string{"SYN"}}},
	}
	s := vxlanScenario(100, &valid, 4789, extra...)
	pkts, err := buildPackets(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	data := pkts[0].Data
	// 定位 VXLAN 头:外层 eth(14) + ipv4(20) + udp(8) = 42 起。
	hdr := data[42:50]
	// flag byte:'I' 位落 0x08,GBP 等扩展位全 0。
	want := []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00}
	if !bytes.Equal(hdr, want) {
		t.Fatalf("VXLAN 头 = %x,期望 %x", hdr, want)
	}
}

// TestBuildVXLANValidIDFlagFalse:valid_id_flag: false 时 'I' 位落 0(非法头畸形)。
func TestBuildVXLANValidIDFlagFalse(t *testing.T) {
	invalid := false
	extra := []scenario.Layer{
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.10", Dst: "192.168.1.20"}},
		{Type: "payload_hex", Fields: scenario.PayloadHex("0xdeadbeef")},
	}
	s := vxlanScenario(100, &invalid, 4789, extra...)
	pkts, err := buildPackets(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	hdr := pkts[0].Data[42:50]
	if hdr[0] != 0x00 {
		t.Fatalf("valid_id_flag=false 时 flag byte = 0x%02x,期望 0x00", hdr[0])
	}
	if !bytes.Equal(hdr[4:7], []byte{0x00, 0x00, 0x64}) {
		t.Fatalf("VNI 字节 = %x,期望 000064", hdr[4:7])
	}
}

// TestBuildVXLANInnerVLAN:内层 eth→vlan→ipv4 串接(inner EtherType 0x8100、
// Dot1Q type 0x0800 由 ethTypeFor 自动推导)。
func TestBuildVXLANInnerVLAN(t *testing.T) {
	extra := []scenario.Layer{
		{Type: "vlan", Fields: &scenario.VLANFields{VID: 500}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.2.10", Dst: "192.168.2.20"}},
		{Type: "udp", Fields: &scenario.UDPFields{SPort: 5353, DPort: 53}},
	}
	s := vxlanScenario(300, nil, 4789, extra...)
	pkts, err := buildPackets(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	data := pkts[0].Data
	// inner eth 头起于 42+8=50;其 EtherType(第 13-14 字节)应为 0x8100(Dot1Q)。
	innerEthType := uint16(data[50+12])<<8 | uint16(data[50+13])
	if innerEthType != 0x8100 {
		t.Fatalf("inner eth EtherType = 0x%04x,期望 0x8100", innerEthType)
	}
	// Dot1Q 头(TCI 2 字节 + type 2 字节,共 4 字节)起于 50+14=64;type 应为 0x0800(IPv4)。
	dot1qType := uint16(data[64+2])<<8 | uint16(data[64+3])
	if dot1qType != 0x0800 {
		t.Fatalf("Dot1Q type = 0x%04x,期望 0x0800", dot1qType)
	}
}

// TestBuildVXLANChecksums:外层 UDP checksum 绑外层 IPv4 伪首部、
// 内层 TCP checksum 绑内层 IPv4 伪首部(两层均非零,且换外层地址只改外层 checksum ——
// 证明内层绑定的是内层 IP,不随外层变化)。
func TestBuildVXLANChecksums(t *testing.T) {
	inner := []scenario.Layer{
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.10", Dst: "192.168.1.20"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 40000, DPort: 80, Flags: []string{"SYN"}}},
	}
	s1 := vxlanScenario(100, nil, 4789, inner...)
	s2 := vxlanScenario(100, nil, 4789, inner...)
	// 改外层 IP:外层 UDP checksum 应变,内层 TCP checksum 应不变。
	s2.Packets[0].Stack[1].Fields.(*scenario.IPv4Fields).Src = "10.0.0.99"

	p1, err := buildPackets(s1)
	if err != nil {
		t.Fatalf("build s1: %v", err)
	}
	p2, err := buildPackets(s2)
	if err != nil {
		t.Fatalf("build s2: %v", err)
	}
	// 外层 UDP checksum 位于 14+20+6 = 40 起。
	outerCsum1 := uint16(p1[0].Data[40])<<8 | uint16(p1[0].Data[41])
	outerCsum2 := uint16(p2[0].Data[40])<<8 | uint16(p2[0].Data[41])
	if outerCsum1 == 0 || outerCsum2 == 0 {
		t.Fatalf("外层 UDP checksum 不应为 0:%x / %x", outerCsum1, outerCsum2)
	}
	if outerCsum1 == outerCsum2 {
		t.Fatalf("外层 IP 变化后外层 UDP checksum 应变化,实际相同(%x)", outerCsum1)
	}
	// 内层 TCP checksum:内层 ipv4 起 50、头 20、tcp 起 70,checksum 在 70+16 = 86 起。
	innerCsum1 := uint16(p1[0].Data[86])<<8 | uint16(p1[0].Data[87])
	innerCsum2 := uint16(p2[0].Data[86])<<8 | uint16(p2[0].Data[87])
	if innerCsum1 == 0 {
		t.Fatalf("内层 TCP checksum 不应为 0")
	}
	if innerCsum1 != innerCsum2 {
		t.Fatalf("外层 IP 变化不应影响内层 TCP checksum(应绑内层 IP):%x != %x", innerCsum1, innerCsum2)
	}
}
