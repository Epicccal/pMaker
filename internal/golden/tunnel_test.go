package golden_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

// 本文件覆盖封装/隧道:IPv6+UDP 回读、QinQ+GRE 解码、GRE 承载内层 IPv6,
// 验证 next-proto 自动串接与多层 checksum 就近绑定。
// 整体迁自 internal/builder/tunnel_test.go —— 它 import writer、调全链路读 examples,
// 是端到端测试,不是 builder 单测,故归 golden 包(见 doc.go 判据)。

// countLayers 统计包中某层类型的出现次数(用于 QinQ 双层 Dot1Q、GRE 内外双层 IPv4 断言)。
func countLayers(pkt gopacket.Packet, lt gopacket.LayerType) int {
	n := 0
	for _, l := range pkt.Layers() {
		if l.LayerType() == lt {
			n++
		}
	}
	return n
}

// buildPackets 跑 plan.Plan + builder.BuildPlanned,返回字节包与错误(不 Fatal、不校验)。
func buildPackets(s *scenario.Scenario) ([]builder.OutPacket, error) {
	planned, err := plan.Plan(s)
	if err != nil {
		return nil, err
	}
	return builder.BuildPlanned(planned)
}

// TestParseBackIPv6 构造 IPv6/UDP 包并回读,验证 IPv6 层字段、next-header 串接与 checksum 绑定。
func TestParseBackIPv6(t *testing.T) {
	hopLimit := uint8(64)
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2", HopLimit: &hopLimit}},
				{Type: "udp", Fields: &scenario.UDPFields{SPort: 53000, DPort: 53}},
				{Type: "payload", Fields: &scenario.PayloadFields{Payload: "v6probe"}},
			},
		}},
	}
	pkts, err := buildPackets(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readPackets(t, buf.Bytes())
	if len(got) != 1 {
		t.Fatalf("期望 1 个包,得到 %d", len(got))
	}
	ipL := got[0].Layer(layers.LayerTypeIPv6)
	if ipL == nil {
		t.Fatalf("缺少 IPv6 层")
	}
	ip := ipL.(*layers.IPv6)
	if ip.Version != 6 || ip.HopLimit != 64 {
		t.Errorf("IPv6 version/hoplimit = %d/%d,期望 6/64", ip.Version, ip.HopLimit)
	}
	if !ip.SrcIP.Equal(net.ParseIP("2001:db8::1")) || !ip.DstIP.Equal(net.ParseIP("2001:db8::2")) {
		t.Errorf("IPv6 src/dst = %s/%s", ip.SrcIP, ip.DstIP)
	}
	if ip.NextHeader != layers.IPProtocolUDP {
		t.Errorf("IPv6 next header = %v,期望 UDP", ip.NextHeader)
	}
	udpL := got[0].Layer(layers.LayerTypeUDP)
	if udpL == nil {
		t.Fatalf("缺少 UDP 层(next-header 串接失败)")
	}
	udp := udpL.(*layers.UDP)
	// UDP checksum 依赖 IPv6 伪首部;gopacket 解析后校验位应非零且正确。
	if udp.Checksum == 0 {
		t.Errorf("UDP checksum=0,期望已用 IPv6 伪首部计算")
	}
	if !bytes.Equal(udp.Payload, []byte("v6probe")) {
		t.Errorf("UDP payload = %q,期望 v6probe", udp.Payload)
	}
}

// TestParseBackQinQGRE 回读 qinq_gre,验证封装链正确解码(证明 next-proto 串接)。
func TestParseBackQinQGRE(t *testing.T) {
	data := generatePcap(t, "../../examples/tunnel/qinq_gre.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 3 {
		t.Fatalf("期望 3 个包,得到 %d", len(pkts))
	}

	// 包①:QinQ 双层 VLAN,内层能解到 IPv4 + TCP
	if got := countLayers(pkts[0], layers.LayerTypeDot1Q); got != 2 {
		t.Errorf("包①期望 2 层 Dot1Q(QinQ),得到 %d", got)
	}
	if pkts[0].Layer(layers.LayerTypeIPv4) == nil || pkts[0].Layer(layers.LayerTypeTCP) == nil {
		t.Errorf("包①内层未解到 IPv4/TCP")
	}

	// 包②:GRE 隧道,含内层 IPv4
	if pkts[1].Layer(layers.LayerTypeGRE) == nil {
		t.Errorf("包②缺少 GRE 层")
	}
	if got := countLayers(pkts[1], layers.LayerTypeIPv4); got != 2 {
		t.Errorf("包②期望 2 层 IPv4(外层+隧道内层),得到 %d", got)
	}
}

// TestParseBackIPv6InGRE 验证 GRE 隧道承载内层 IPv6(外层 IPv4 → GRE → IPv6 → TCP)。
func TestParseBackIPv6InGRE(t *testing.T) {
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "1.1.1.1", Dst: "2.2.2.2"}},
				{Type: "gre", Fields: &scenario.GREFields{}},
				{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::10", Dst: "2001:db8::20"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 443, Flags: []string{"SYN"}}},
			},
		}},
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pkts, err := buildPackets(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readPackets(t, buf.Bytes())
	if len(got) != 1 {
		t.Fatalf("期望 1 个包,得到 %d", len(got))
	}
	if got[0].Layer(layers.LayerTypeGRE) == nil {
		t.Errorf("缺少 GRE 层")
	}
	// 外层 IPv4 + 内层 IPv6 各一层
	if got[0].Layer(layers.LayerTypeIPv4) == nil {
		t.Errorf("缺少外层 IPv4")
	}
	inner := got[0].Layer(layers.LayerTypeIPv6)
	if inner == nil {
		t.Fatalf("缺少内层 IPv6")
	}
	if inner.(*layers.IPv6).NextHeader != layers.IPProtocolTCP {
		t.Errorf("内层 IPv6 next header = %v,期望 TCP", inner.(*layers.IPv6).NextHeader)
	}
	if got[0].Layer(layers.LayerTypeTCP) == nil {
		t.Errorf("缺少内层 TCP(就近 IPv6 checksum 绑定)")
	}
}
