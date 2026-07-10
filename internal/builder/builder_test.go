package builder_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

// genPcap 跑完整链路 scenario -> builder -> writer,返回 pcap 字节。
func genPcap(t *testing.T, path string) ([]byte, string) {
	t.Helper()
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pkts, err := builder.Build(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write: %v", err)
	}
	return buf.Bytes(), s.LinkType
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
	pkts, err := builder.Build(s)
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
	data, _ := genPcap(t, "../../examples/http_stack.yaml")
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

// TestParseBackQinQGRE 回读 qinq_gre,验证封装链正确解码(证明 next-proto 串接)。
func TestParseBackQinQGRE(t *testing.T) {
	data, _ := genPcap(t, "../../examples/qinq_gre.yaml")
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
	pkts, err := builder.Build(s)
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
	pkts, err := builder.Build(s)
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
