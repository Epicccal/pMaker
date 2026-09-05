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

// TestParseBackVLANEdge 回读 vlan_edge,锁定 VLAN 显式覆盖与 VID 边界的 wire 落值:
// 非标外层 TPID(0x9100)、中间层 type 非标(0x88a8)、type 断链(0xffff)、
// VID 0(priority tag)与 4095(12 位最大值)。
func TestParseBackVLANEdge(t *testing.T) {
	data := generatePcap(t, "../../examples/tunnel/vlan_edge.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 5 {
		t.Fatalf("期望 5 个包,得到 %d", len(pkts))
	}

	// 包①:eth.ethertype=0x9100 非标 TPID。gopacket 默认不把 0x9100 解为 Dot1Q,
	// 回读在此断链(DecodeFailure),断言的是 eth 层写出的 EtherType 原值。
	ethL := pkts[0].LinkLayer().(*layers.Ethernet)
	if ethL.EthernetType != 0x9100 {
		t.Errorf("包① eth.EthernetType = %#x,期望 0x9100(非标外层 TPID 原样落 wire)", ethL.EthernetType)
	}

	// 包②:中间层 type=0x88a8 落在外层标签的 Type 上;内层标签可继续解到 IPv4。
	vlans := vlanLayers(pkts[1].Layers())
	if len(vlans) < 2 {
		t.Fatalf("包②期望 2 层 Dot1Q,得到 %d", len(vlans))
	}
	if vlans[0].Type != 0x88a8 {
		t.Errorf("包②外层 Dot1Q.Type = %#x,期望 0x88a8(type 覆盖)", vlans[0].Type)
	}
	if vlans[1].Type != layers.EthernetTypeIPv4 {
		t.Errorf("包②内层 Dot1Q.Type = %#x,期望 0x0800(自动推导)", vlans[1].Type)
	}
	if vlans[0].VLANIdentifier != 100 || vlans[1].VLANIdentifier != 200 {
		t.Errorf("包② VID = %d/%d,期望 100/200", vlans[0].VLANIdentifier, vlans[1].VLANIdentifier)
	}

	// 包③:type=0xffff 断链。断链是刻意构造,回读解析在标签处停止,
	// 断言 Dot1Q.Type 原样保留 0xffff。
	vlans = vlanLayers(pkts[2].Layers())
	if len(vlans) != 1 || vlans[0].Type != 0xffff {
		t.Errorf("包③期望 1 层 Dot1Q 且 Type=0xffff,得到 %d 层", len(vlans))
	}

	// 包④⑤:VID 边界值原样落 wire(0 = priority tag,4095 = 12 位最大值)。
	vlans = vlanLayers(pkts[3].Layers())
	if len(vlans) != 1 || vlans[0].VLANIdentifier != 0 {
		t.Errorf("包④期望 VID=0(priority tag),得到 %v", vlans)
	}
	vlans = vlanLayers(pkts[4].Layers())
	if len(vlans) != 1 || vlans[0].VLANIdentifier != 4095 {
		t.Errorf("包⑤期望 VID=4095,得到 %v", vlans)
	}
}

// vlanLayers 收集 gopacket 回读后的 Dot1Q 层。
func vlanLayers(ls []gopacket.Layer) []*layers.Dot1Q {
	var out []*layers.Dot1Q
	for _, l := range ls {
		if d, ok := l.(*layers.Dot1Q); ok {
			out = append(out, d)
		}
	}
	return out
}
