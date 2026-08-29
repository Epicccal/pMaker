package builder_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 ICMPv4 构包:quote_from 切片、Redirect/ParamProblem/FragNeeded 的
// 特殊字段编码,以及 gateway/pointer/mtu 误用类型时的报错。

func TestICMPQuoteFromUsesRFC792Slice(t *testing.T) {
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{
			{
				Name: "udp-probe",
				Stack: []scenario.Layer{
					{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
					{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.1", TTL: u8ptr(64)}},
					{Type: "udp", Fields: &scenario.UDPFields{SPort: 40000, DPort: 65000}},
					{Type: "payload", Fields: &scenario.PayloadFields{Payload: "abcdefghijklmnop"}},
				},
			},
			{
				Stack: []scenario.Layer{
					{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:02", Dst: "00:00:00:00:00:01"}},
					{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.10", TTL: u8ptr(64)}},
					{Type: "icmp", Fields: &scenario.ICMPFields{
						Type:      yaml.Node{Kind: yaml.ScalarNode, Value: "destination_unreachable"},
						Code:      yaml.Node{Kind: yaml.ScalarNode, Value: "port_unreachable"},
						QuoteFrom: "udp-probe",
					}},
				},
			},
		},
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pkts, err := buildPackets(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	orig := gopacket.NewPacket(pkts[0].Data, layers.LayerTypeEthernet, gopacket.Default)
	origIP := orig.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	want := append([]byte{}, origIP.Contents...)
	want = append(want, origIP.Payload[:8]...)

	reply := gopacket.NewPacket(pkts[1].Data, layers.LayerTypeEthernet, gopacket.Default)
	icmp := reply.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !bytes.Equal(icmp.Payload, want) {
		t.Fatalf("quote_from payload=%x,期望 %x", icmp.Payload, want)
	}
	if len(icmp.Payload) != 28 {
		t.Fatalf("quote_from 长度=%d,期望 28", len(icmp.Payload))
	}
	inner := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.Default)
	udp := inner.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if uint16(udp.SrcPort) != 40000 || uint16(udp.DstPort) != 65000 {
		t.Fatalf("quote_from 未包含 UDP 端口:sport=%d dport=%d", udp.SrcPort, udp.DstPort)
	}
}

// icmpv4ProbeStack:eth/ipv4/udp/payload,供 quote_from 引用。
func icmpv4ProbeStack() []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.1", TTL: u8ptr(64)}},
		{Type: "udp", Fields: &scenario.UDPFields{SPort: 40000, DPort: 65000}},
		{Type: "payload", Fields: &scenario.PayloadFields{Payload: "abcdefghijklmnop"}},
	}
}

// icmpv4ErrorScenario 构造 udp-probe + 一条 ICMPv4 错误报文(quote_from)。
func icmpv4ErrorScenario(typ, code string, f *scenario.ICMPFields) *scenario.Scenario {
	f.Type = yaml.Node{Kind: yaml.ScalarNode, Value: typ}
	f.Code = yaml.Node{Kind: yaml.ScalarNode, Value: code}
	f.QuoteFrom = "udp-probe"
	return &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{
		{Name: "udp-probe", Stack: icmpv4ProbeStack()},
		{Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:02", Dst: "00:00:00:00:00:01"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.10", TTL: u8ptr(64)}},
			{Type: "icmp", Fields: f},
		}},
	}}
}

// TestParseBackICMPv4Redirect 验证 Redirect 的 Gateway IPv4 字段(RFC 792)。
func TestParseBackICMPv4Redirect(t *testing.T) {
	gw := "10.0.0.254"
	data := buildScenarioPcap(t, icmpv4ErrorScenario("redirect", "1", &scenario.ICMPFields{Gateway: &gw}))
	pkts := readPcapPackets(t, data)
	icmp := pkts[1].Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if icmp.TypeCode.Type() != 5 {
		t.Fatalf("type=%d,期望 5", icmp.TypeCode.Type())
	}
	// Gateway IPv4 在 bytes 4-7 = gopacket Id(bytes 4-5)+Seq(bytes 6-7)。
	got := make([]byte, 4)
	binary.BigEndian.PutUint16(got[0:2], icmp.Id)
	binary.BigEndian.PutUint16(got[2:4], icmp.Seq)
	if !net.ParseIP(gw).To4().Equal(got) {
		t.Fatalf("gateway=%v,期望 %s", net.IP(got), gw)
	}
}

// TestParseBackICMPv4ParamProblem 验证 Parameter Problem 的 Pointer 字段(RFC 792)。
func TestParseBackICMPv4ParamProblem(t *testing.T) {
	pointer := uint8(20)
	data := buildScenarioPcap(t, icmpv4ErrorScenario("parameter_problem", "0", &scenario.ICMPFields{Pointer: &pointer}))
	pkts := readPcapPackets(t, data)
	icmp := pkts[1].Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if icmp.TypeCode.Type() != 12 {
		t.Fatalf("type=%d,期望 12", icmp.TypeCode.Type())
	}
	// Pointer 在 byte 4 = Id 高字节。
	if got := byte(icmp.Id >> 8); got != pointer {
		t.Fatalf("pointer=%d,期望 %d", got, pointer)
	}
}

// TestParseBackICMPv4FragNeededMTU 验证 Dest Unreachable code 4 的 MTU 字段(RFC 1191)。
func TestParseBackICMPv4FragNeededMTU(t *testing.T) {
	mtu := uint16(1492)
	data := buildScenarioPcap(t, icmpv4ErrorScenario("destination_unreachable", "fragmentation_needed", &scenario.ICMPFields{MTU: &mtu}))
	pkts := readPcapPackets(t, data)
	icmp := pkts[1].Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if icmp.TypeCode.Type() != 3 || icmp.TypeCode.Code() != 4 {
		t.Fatalf("type/code=%d/%d,期望 3/4", icmp.TypeCode.Type(), icmp.TypeCode.Code())
	}
	// MTU 在 bytes 6-7 = Seq。
	if icmp.Seq != mtu {
		t.Fatalf("mtu=%d,期望 %d", icmp.Seq, mtu)
	}
}

// TestICMPv4FieldsOnWrongType 验证 gateway/pointer/mtu 误用类型时构建报错。
func TestICMPv4FieldsOnWrongType(t *testing.T) {
	gw := "10.0.0.254"
	// gateway 用于 dest_unreachable 应报错
	s := icmpv4ErrorScenario("destination_unreachable", "port_unreachable", &scenario.ICMPFields{Gateway: &gw})
	if _, err := buildPackets(s); err == nil {
		t.Fatal("期望 gateway 用于 dest_unreachable 时报错,实际成功")
	}
	// mtu 用于 port_unreachable(code 3)应报错
	mtu := uint16(1492)
	s2 := icmpv4ErrorScenario("destination_unreachable", "port_unreachable", &scenario.ICMPFields{MTU: &mtu})
	if _, err := buildPackets(s2); err == nil {
		t.Fatal("期望 mtu 用于 code 3 时报错,实际成功")
	}
}

// TestICMPv4ChecksumOverride 显式写 0xdead → 回读等于 0xdead(关闭自动计算,值原样上 wire)。
func TestICMPv4ChecksumOverride(t *testing.T) {
	f := &scenario.ICMPFields{
		Type:       yaml.Node{Kind: yaml.ScalarNode, Value: "echo_request"},
		ID:         hexPtr(0x1234),
		Seq:        1,
		PayloadHex: "0x68656c6c6f",
		Checksum:   hexPtr(0xdead),
	}
	s := &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "icmp", Fields: f},
		},
	}}}
	pkts := readPackets(t, buildScenarioPcap(t, s))
	icmp := pkts[0].Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if icmp.Checksum != 0xdead {
		t.Fatalf("icmp checksum = %#x,期望 0xdead", icmp.Checksum)
	}
}

// TestICMPv4ChecksumAuto 未写 checksum → 自动计算非零(防止接线时误关自动计算)。
func TestICMPv4ChecksumAuto(t *testing.T) {
	f := &scenario.ICMPFields{
		Type:       yaml.Node{Kind: yaml.ScalarNode, Value: "echo_request"},
		ID:         hexPtr(0x1234),
		Seq:        1,
		PayloadHex: "0x68656c6c6f",
	}
	s := &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "icmp", Fields: f},
		},
	}}}
	pkts := readPackets(t, buildScenarioPcap(t, s))
	icmp := pkts[0].Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if icmp.Checksum == 0 {
		t.Fatalf("icmp checksum=0,期望自动计算非零")
	}
}
