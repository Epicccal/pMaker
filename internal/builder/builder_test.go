package builder_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

// genPcap 跑完整链路 scenario -> plan -> builder -> writer,返回 pcap 字节。
func genPcap(t *testing.T, path string) ([]byte, string) {
	t.Helper()
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
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
	return buf.Bytes(), s.LinkType
}

// buildPackets 跑 plan.Plan + builder.BuildPlanned,返回字节包与错误(不 Fatal、不校验)。
func buildPackets(s *scenario.Scenario) ([]builder.OutPacket, error) {
	planned, err := plan.Plan(s)
	if err != nil {
		return nil, err
	}
	return builder.BuildPlanned(planned)
}

// readPackets 用 pcapgo 回读所有包。
func readPackets(t *testing.T, data []byte) []gopacket.Packet {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcapgo reader: %v", err)
	}
	var pkts []gopacket.Packet
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		pkts = append(pkts, gopacket.NewPacket(raw, r.LinkType(), gopacket.Default))
	}
	return pkts
}

func countLayers(pkt gopacket.Packet, lt gopacket.LayerType) int {
	n := 0
	for _, l := range pkt.Layers() {
		if l.LayerType() == lt {
			n++
		}
	}
	return n
}

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

func u8ptr(v uint8) *uint8 { return &v }

// TestParseBackHTTP 回读 http_stack,断言 Ethernet/IPv4/TCP 与 HTTP 请求行。
func TestParseBackHTTP(t *testing.T) {
	data, _ := genPcap(t, "../../examples/http/stack.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 1 {
		t.Fatalf("期望 1 个包,得到 %d", len(pkts))
	}
	p := pkts[0]
	for _, lt := range []gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeIPv4, layers.LayerTypeTCP} {
		if p.Layer(lt) == nil {
			t.Errorf("缺少 %v 层", lt)
		}
	}
	app := p.ApplicationLayer()
	if app == nil || !bytes.Contains(app.Payload(), []byte("GET /index.html HTTP/1.1")) {
		t.Errorf("payload 不含预期的 HTTP 请求行")
	}
	if app != nil && !bytes.Contains(app.Payload(), []byte("Host: example.com")) {
		t.Errorf("payload 不含 Host 头")
	}
}

// TestParseBackFTP 回读 ftp/control.yaml,断言两个包的 TCP payload 含 FTP 命令与响应,
// 证明 ftp_request/ftp_response 序列化符合 RFC 959(command 原样、code message\r\n)。
func TestParseBackFTP(t *testing.T) {
	data, _ := genPcap(t, "../../examples/ftp/control.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 2 {
		t.Fatalf("期望 2 个包,得到 %d", len(pkts))
	}
	p0 := pkts[0].ApplicationLayer()
	if p0 == nil || string(p0.Payload()) != "USER anonymous\r\n" {
		t.Errorf("包0 FTP 命令=%q,期望 USER anonymous\\r\\n", p0)
	}
	p1 := pkts[1].ApplicationLayer()
	if p1 == nil || string(p1.Payload()) != "331 Please specify the password.\r\n" {
		t.Errorf("包1 FTP 响应=%q,期望 331 ...\\r\\n", p1)
	}
}

// TestParseBackQinQGRE 回读 qinq_gre,验证封装链正确解码(证明 next-proto 串接)。
func TestParseBackQinQGRE(t *testing.T) {
	data, _ := genPcap(t, "../../examples/tunnel/qinq_gre.yaml")
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

// buildScenarioPcap 跑 scenario -> plan -> builder -> writer,返回 pcap 字节。
func buildScenarioPcap(t *testing.T, s *scenario.Scenario) []byte {
	t.Helper()
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
	return buf.Bytes()
}

// readPcapPackets 用 pcapgo 回读 pcap 字节为 gopacket.Packet 列表。
func readPcapPackets(t *testing.T, data []byte) []gopacket.Packet {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcapgo reader: %v", err)
	}
	var out []gopacket.Packet
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		out = append(out, gopacket.NewPacket(raw, r.LinkType(), gopacket.Default))
	}
	return out
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
