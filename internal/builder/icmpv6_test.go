package builder_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

// 本文件覆盖 ICMPv6 构包:echo request 回读、Dest Unreachable/Packet Too Big/
// Parameter Problem 的特殊字段编码与 quote 截断,以及 mtu/pointer 误用类型时的报错。

// TestParseBackICMPv6 构造 eth/ipv6/icmpv6 echo 并回读,验证 LayerTypeICMPv6 +
// LayerTypeICMPv6Echo、IPv6 NextHeader 串接与伪首部 checksum 绑定。
func TestParseBackICMPv6(t *testing.T) {
	id := scenario.Hex(0x1234)
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2"}},
				{Type: "icmpv6", Fields: &scenario.ICMPv6Fields{
					Type:       yaml.Node{Kind: yaml.ScalarNode, Value: "echo_request"},
					ID:         &id,
					Seq:        1,
					PayloadHex: "0x68656c6c6f",
				}},
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
	ip := got[0].Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if ip.NextHeader != layers.IPProtocolICMPv6 {
		t.Errorf("IPv6 next header = %v,期望 ICMPv6", ip.NextHeader)
	}
	icmpL := got[0].Layer(layers.LayerTypeICMPv6)
	if icmpL == nil {
		t.Fatalf("缺少 ICMPv6 层")
	}
	icmp := icmpL.(*layers.ICMPv6)
	if icmp.TypeCode.Type() != 128 || icmp.TypeCode.Code() != 0 {
		t.Errorf("ICMPv6 type/code = %d/%d,期望 128/0", icmp.TypeCode.Type(), icmp.TypeCode.Code())
	}
	// 校验和依赖 IPv6 伪首部;非零证明已就近绑定内层 IPv6。
	if icmp.Checksum == 0 {
		t.Errorf("ICMPv6 checksum=0,期望已用 IPv6 伪首部计算")
	}
	echoL := got[0].Layer(layers.LayerTypeICMPv6Echo)
	if echoL == nil {
		t.Fatalf("缺少 ICMPv6Echo 层")
	}
	echo := echoL.(*layers.ICMPv6Echo)
	if echo.Identifier != 0x1234 || echo.SeqNumber != 1 {
		t.Errorf("echo id/seq = %#x/%d,期望 0x1234/1", echo.Identifier, echo.SeqNumber)
	}
	// echo 数据跟在 4 字节 echo 头之后;gopacket 的 ICMPv6Echo 未设置 BaseLayer,
	// 数据落在 ICMPv6 层 payload 中。
	if !bytes.Equal(icmp.LayerPayload()[4:], []byte("hello")) {
		t.Errorf("echo payload = %q,期望 hello", icmp.LayerPayload()[4:])
	}
}

// icmpv6ProbeStack:eth/ipv6/udp/payload,供 quote_from 引用。
func icmpv6ProbeStack() []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::10", Dst: "2001:db8::1"}},
		{Type: "udp", Fields: &scenario.UDPFields{SPort: 40000, DPort: 65000}},
		{Type: "payload", Fields: &scenario.PayloadFields{Payload: "abcdefghijklmnop"}},
	}
}

// icmpv6ErrorScenario 构造 udp-probe + 一条 ICMPv6 错误报文(quote_from)。
func icmpv6ErrorScenario(typ, code string, f *scenario.ICMPv6Fields) *scenario.Scenario {
	f.Type = yaml.Node{Kind: yaml.ScalarNode, Value: typ}
	f.Code = yaml.Node{Kind: yaml.ScalarNode, Value: code}
	f.QuoteFrom = "udp-probe"
	return &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{
		{Name: "udp-probe", Stack: icmpv6ProbeStack()},
		{Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:02", Dst: "00:00:00:00:00:01"}},
			{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::10"}},
			{Type: "icmpv6", Fields: f},
		}},
	}}
}

// TestParseBackICMPv6Error 验证 Dest Unreachable 的 RFC 4443 合规结构:
// ICMPv6 头(4) + Unused(4,必为 0) + quote,quote 起始于偏移 8 而非 4。
func TestParseBackICMPv6Error(t *testing.T) {
	data := buildScenarioPcap(t, icmpv6ErrorScenario("destination_unreachable", "port_unreachable", &scenario.ICMPv6Fields{}))
	pkts := readPcapPackets(t, data)
	icmp := pkts[1].Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if icmp.TypeCode.Type() != 1 || icmp.TypeCode.Code() != 4 {
		t.Fatalf("type/code=%d/%d,期望 1/4", icmp.TypeCode.Type(), icmp.TypeCode.Code())
	}
	// ICMPv6 payload = Unused(4) + quote(IPv6 40 + UDP 8 + payload 16 = 64) = 68
	if len(icmp.Payload) != 68 {
		t.Fatalf("payload 长度=%d,期望 68", len(icmp.Payload))
	}
	if !bytes.Equal(icmp.Payload[:4], make([]byte, 4)) {
		t.Fatalf("Unused 字段非零: %x", icmp.Payload[:4])
	}
	quote := icmp.Payload[4:]
	inner := gopacket.NewPacket(quote, layers.LayerTypeIPv6, gopacket.Default)
	if inner.Layer(layers.LayerTypeIPv6) == nil {
		t.Fatalf("quote 未解析出内层 IPv6: %x", quote)
	}
	udp := inner.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if uint16(udp.SrcPort) != 40000 || uint16(udp.DstPort) != 65000 {
		t.Fatalf("内层 UDP 端口: sport=%d dport=%d", udp.SrcPort, udp.DstPort)
	}
	// checksum 必须覆盖 头+Unused+quote;非零且可被 gopacket 回读验证。
	if icmp.Checksum == 0 {
		t.Fatal("ICMPv6 checksum=0,期望含伪首部计算")
	}
}

// TestParseBackICMPv6PacketTooBig 验证 Packet Too Big 的 MTU 字段(RFC 4443 §3.2)。
func TestParseBackICMPv6PacketTooBig(t *testing.T) {
	mtu := uint32(1280)
	data := buildScenarioPcap(t, icmpv6ErrorScenario("packet_too_big", "0", &scenario.ICMPv6Fields{MTU: &mtu}))
	pkts := readPcapPackets(t, data)
	icmp := pkts[1].Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if icmp.TypeCode.Type() != 2 {
		t.Fatalf("type=%d,期望 2", icmp.TypeCode.Type())
	}
	// 前 4 字节为 MTU(大端),之后才是 quote。
	gotMTU := binary.BigEndian.Uint32(icmp.Payload[:4])
	if gotMTU != 1280 {
		t.Fatalf("MTU=%d,期望 1280", gotMTU)
	}
	if len(icmp.Payload) < 4+40 {
		t.Fatalf("payload=%d,期望至少 44(MTU 4 + IPv6 头 40)", len(icmp.Payload))
	}
}

// TestParseBackICMPv6ParamProblem 验证 Parameter Problem 的 Pointer 字段(RFC 4443 §3.4)。
func TestParseBackICMPv6ParamProblem(t *testing.T) {
	pointer := uint32(6)
	data := buildScenarioPcap(t, icmpv6ErrorScenario("parameter_problem", "0", &scenario.ICMPv6Fields{Pointer: &pointer}))
	pkts := readPcapPackets(t, data)
	icmp := pkts[1].Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if icmp.TypeCode.Type() != 4 {
		t.Fatalf("type=%d,期望 4", icmp.TypeCode.Type())
	}
	gotPtr := binary.BigEndian.Uint32(icmp.Payload[:4])
	if gotPtr != 6 {
		t.Fatalf("pointer=%d,期望 6", gotPtr)
	}
}

// TestParseBackICMPv6ErrorBigQuote 验证大触发包的 quote 截断:外层 IPv6 包 ≤ 1280,
// quote ≤ 1232(开销 40+8)。
func TestParseBackICMPv6ErrorBigQuote(t *testing.T) {
	big := make([]byte, 2000)
	for i := range big {
		big[i] = byte('A' + i%26)
	}
	s := &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{
		{Name: "big-probe", Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::10", Dst: "2001:db8::1"}},
			{Type: "udp", Fields: &scenario.UDPFields{SPort: 40000, DPort: 65000}},
			{Type: "payload", Fields: &scenario.PayloadFields{Payload: string(big)}},
		}},
		{Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:02", Dst: "00:00:00:00:00:01"}},
			{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::10"}},
			{Type: "icmpv6", Fields: &scenario.ICMPv6Fields{
				Type:      yaml.Node{Kind: yaml.ScalarNode, Value: "destination_unreachable"},
				Code:      yaml.Node{Kind: yaml.ScalarNode, Value: "port_unreachable"},
				QuoteFrom: "big-probe",
			}},
		}},
	}}
	data := buildScenarioPcap(t, s)
	pkts := readPcapPackets(t, data)
	ip := pkts[1].Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if total := int(ip.Length) + 40; total > 1280 {
		t.Fatalf("外层 IPv6 包=%d,期望 ≤ 1280", total)
	}
	icmp := pkts[1].Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	// payload = Unused(4) + quote;quote ≤ 1232 => payload ≤ 1236
	if len(icmp.Payload) > 1236 {
		t.Fatalf("ICMPv6 payload=%d,期望 ≤ 1236(Unused 4 + quote≤1232)", len(icmp.Payload))
	}
	if !bytes.Equal(icmp.Payload[:4], make([]byte, 4)) {
		t.Fatalf("Unused 字段非零: %x", icmp.Payload[:4])
	}
}

// TestICMPv6MTUOnWrongType 验证 mtu/pointer 字段误用时构建报错。
func TestICMPv6MTUOnWrongType(t *testing.T) {
	mtu := uint32(1280)
	s := &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2"}},
			{Type: "icmpv6", Fields: &scenario.ICMPv6Fields{
				Type: yaml.Node{Kind: yaml.ScalarNode, Value: "echo_request"},
				MTU:  &mtu,
			}},
		},
	}}}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := buildPackets(s); err == nil {
		t.Fatal("期望 mtu 用于 echo 时构建报错,实际成功")
	}
}

// TestICMPv6ChecksumOverride 显式写 0xdead → 回读等于 0xdead(关闭自动计算,值原样上 wire)。
func TestICMPv6ChecksumOverride(t *testing.T) {
	s := &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2"}},
			{Type: "icmpv6", Fields: &scenario.ICMPv6Fields{
				Type:       yaml.Node{Kind: yaml.ScalarNode, Value: "echo_request"},
				ID:         hexPtr(0x1234),
				Seq:        1,
				PayloadHex: "0x68656c6c6f",
				Checksum:   hexPtr(0xdead),
			}},
		},
	}}}
	pkts := readPackets(t, buildScenarioPcap(t, s))
	icmp := pkts[0].Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if icmp.Checksum != 0xdead {
		t.Fatalf("icmpv6 checksum = %#x,期望 0xdead", icmp.Checksum)
	}
}

// TestICMPv6ChecksumAuto 未写 checksum → 自动计算非零(防止接线时误关自动计算)。
func TestICMPv6ChecksumAuto(t *testing.T) {
	s := &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2"}},
			{Type: "icmpv6", Fields: &scenario.ICMPv6Fields{
				Type:       yaml.Node{Kind: yaml.ScalarNode, Value: "echo_request"},
				ID:         hexPtr(0x1234),
				Seq:        1,
				PayloadHex: "0x68656c6c6f",
			}},
		},
	}}}
	pkts := readPackets(t, buildScenarioPcap(t, s))
	icmp := pkts[0].Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if icmp.Checksum == 0 {
		t.Fatalf("icmpv6 checksum=0,期望自动计算非零")
	}
}
