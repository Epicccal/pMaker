package scenario_test

import (
	"bytes"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/flow"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

var update = flag.Bool("update", false, "regenerate golden pcap files")

// TestExamplesGolden 把 examples/ 下每个 YAML 都作为正式测试用例。
// 新增示例时,这里会自动要求生成对应的 testdata/<name>.pcap。
func TestExamplesGolden(t *testing.T) {
	files, err := filepath.Glob("../../examples/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("examples 目录下没有 yaml 用例")
	}

	for _, src := range files {
		name := strings.TrimSuffix(filepath.Base(src), filepath.Ext(src))
		t.Run(name, func(t *testing.T) {
			got := generatePcap(t, src)
			golden := filepath.Join("testdata", name+".pcap")
			if *update {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}

			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("读取 golden 失败(首次请加 -update): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("与 golden 不一致(%d vs %d 字节)", len(got), len(want))
			}
		})
	}
}

func TestHTTPKeepaliveLFIContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/http_keepalive_lfi.yaml")
	for _, want := range [][]byte{
		[]byte("GET /robots.txt HTTP/1.1"),
		[]byte("HTTP/1.1 404 Not Found"),
		[]byte("GET /../etc/passwd HTTP/1.1"),
		[]byte("root:x:0:0:root:/root:/bin/bash"),
		[]byte("hab:x:1000:1000::/home/hab:/usr/bin/zsh"),
	} {
		if !bytes.Contains(pcap, want) {
			t.Fatalf("pcap 不含 %q", want)
		}
	}
}

func TestICMPEchoContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/icmp_echo.yaml")
	icmpPackets := readICMPPackets(t, pcap)
	if len(icmpPackets) != 2 {
		t.Fatalf("期望 2 个 ICMP 包,得到 %d", len(icmpPackets))
	}

	req := icmpPackets[0]
	if req.TypeCode.Type() != 8 || req.TypeCode.Code() != 0 || req.Id != 0x1234 || req.Seq != 1 || string(req.Payload) != "hello" {
		t.Fatalf("echo request 不符合预期:type=%d code=%d id=%#x seq=%d payload=%q", req.TypeCode.Type(), req.TypeCode.Code(), req.Id, req.Seq, req.Payload)
	}
	rep := icmpPackets[1]
	if rep.TypeCode.Type() != 0 || rep.TypeCode.Code() != 0 || rep.Id != 0x1234 || rep.Seq != 1 || string(rep.Payload) != "hello" {
		t.Fatalf("echo reply 不符合预期:type=%d code=%d id=%#x seq=%d payload=%q", rep.TypeCode.Type(), rep.TypeCode.Code(), rep.Id, rep.Seq, rep.Payload)
	}
}

func TestICMPv6EchoContent(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/icmpv6_echo.yaml"))
	icmpv6Pkts := []*layers.ICMPv6{}
	for _, p := range pkts {
		if l := p.Layer(layers.LayerTypeICMPv6); l != nil {
			icmpv6Pkts = append(icmpv6Pkts, l.(*layers.ICMPv6))
		}
	}
	if len(icmpv6Pkts) != 2 {
		t.Fatalf("期望 2 个 ICMPv6 包,得到 %d", len(icmpv6Pkts))
	}

	for i, want := range []struct{ typ uint8 }{{128}, {129}} {
		p := pkts[i]
		icmp := icmpv6Pkts[i]
		if icmp.TypeCode.Type() != want.typ || icmp.TypeCode.Code() != 0 {
			t.Fatalf("包%d type/code 不符合预期:type=%d code=%d", i, icmp.TypeCode.Type(), icmp.TypeCode.Code())
		}
		// 校验和依赖 IPv6 伪首部;非零证明伪首部已绑定生效。
		if icmp.Checksum == 0 {
			t.Fatalf("包%d ICMPv6 checksum=0,期望已用 IPv6 伪首部计算", i)
		}
		echoL := p.Layer(layers.LayerTypeICMPv6Echo)
		if echoL == nil {
			t.Fatalf("包%d 缺少 ICMPv6Echo 层", i)
		}
		echo := echoL.(*layers.ICMPv6Echo)
		if echo.Identifier != 0x1234 || echo.SeqNumber != 1 {
			t.Fatalf("包%d echo 不符合预期:id=%#x seq=%d", i, echo.Identifier, echo.SeqNumber)
		}
		// echo 数据跟在 4 字节 echo 头(identifier/seq)之后;
		// gopacket 的 ICMPv6Echo 未设置 BaseLayer,echo 数据落在 ICMPv6 层 payload 中。
		echoData := icmp.LayerPayload()[4:]
		if !bytes.Equal(echoData, []byte("hello")) {
			t.Fatalf("包%d echo payload=%q,期望 hello", i, echoData)
		}
	}
}

func TestICMPv6QuoteContent(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/icmpv6_quote_from.yaml"))
	if len(pkts) != 2 {
		t.Fatalf("期望 2 个包,得到 %d", len(pkts))
	}

	// 触发包:eth/ipv6/udp/payload,取其 IPv6 头(40B)+ 后续 8B 作期望 quote。
	orig := pkts[0]
	origIP := orig.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	wantQuote := append([]byte{}, origIP.Contents...)
	wantQuote = append(wantQuote, origIP.Payload[:8]...)

	reply := pkts[1]
	icmpL := reply.Layer(layers.LayerTypeICMPv6)
	if icmpL == nil {
		t.Fatal("响应包缺少 ICMPv6 层")
	}
	icmp := icmpL.(*layers.ICMPv6)
	if icmp.TypeCode.Type() != 1 || icmp.TypeCode.Code() != 4 { // dest_unreachable / port_unreachable
		t.Fatalf("type/code 不符合预期:type=%d code=%d", icmp.TypeCode.Type(), icmp.TypeCode.Code())
	}
	if icmp.Checksum == 0 {
		t.Fatal("ICMPv6 checksum=0,期望已用 IPv6 伪首部计算")
	}
	// RFC 4443 quote = IPv6 头(40)+ 8 字节。
	if len(icmp.Payload) != 48 {
		t.Fatalf("quote 长度=%d,期望 48", len(icmp.Payload))
	}
	if !bytes.Equal(icmp.Payload, wantQuote) {
		t.Fatalf("quote payload=%x,期望 %x", icmp.Payload, wantQuote)
	}
	inner := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv6, gopacket.Default)
	if inner.Layer(layers.LayerTypeIPv6) == nil {
		t.Fatalf("quote 未解析出内层 IPv6: %x", icmp.Payload)
	}
	udp := inner.Layer(layers.LayerTypeUDP)
	if udp == nil {
		t.Fatal("quote 未解析出内层 UDP(8 字节应含 UDP 头)")
	}
	if uint16(udp.(*layers.UDP).SrcPort) != 40000 || uint16(udp.(*layers.UDP).DstPort) != 65000 {
		t.Fatalf("内层 UDP 端口不符合预期:sport=%d dport=%d", udp.(*layers.UDP).SrcPort, udp.(*layers.UDP).DstPort)
	}
}

func TestICMPAbnormalContent(t *testing.T) {
	t.Run("named", func(t *testing.T) {
		pkts := readPackets(t, generatePcap(t, "../../examples/icmp_abnormal_named.yaml"))
		cases := []icmpQuoteCase{
			{typ: 3, code: 0, src: "10.0.0.10", dst: "10.0.0.1", ttl: 64, sport: 40000, dport: 65000, payload: []byte("probe net")},
			{typ: 3, code: 1, src: "10.0.0.10", dst: "10.0.0.2", ttl: 64, sport: 40000, dport: 65001, payload: []byte("probe host")},
			{typ: 3, code: 2, src: "10.0.0.10", dst: "10.0.0.3", ttl: 64, sport: 40000, dport: 65002, payload: []byte("probe protocol")},
			{typ: 3, code: 3, src: "10.0.0.10", dst: "10.0.0.4", ttl: 64, sport: 40000, dport: 65003, payload: []byte("probe port")},
			{typ: 3, code: 4, src: "10.0.0.10", dst: "10.0.0.5", ttl: 64, sport: 40000, dport: 65004, payload: []byte("probe frag")},
			{typ: 3, code: 5, src: "10.0.0.10", dst: "10.0.0.6", ttl: 64, sport: 40000, dport: 65005, payload: []byte("probe route")},
			{typ: 11, code: 0, src: "10.0.0.10", dst: "8.8.8.8", ttl: 1, sport: 40000, dport: 65006, payload: []byte("probe ttl")},
			{typ: 11, code: 1, src: "10.0.0.10", dst: "8.8.4.4", ttl: 64, sport: 40000, dport: 65007, payload: []byte("probe reassembly")},
		}
		assertICMPQuoteCases(t, pkts, cases)
	})

	t.Run("numeric", func(t *testing.T) {
		pkts := readPackets(t, generatePcap(t, "../../examples/icmp_abnormal_numeric.yaml"))
		cases := []icmpQuoteCase{
			{typ: 5, code: 1, src: "10.0.0.10", dst: "10.0.0.20", ttl: 64, sport: 40000, dport: 65000, payload: []byte("probe redirect")},
			{typ: 12, code: 0, src: "10.0.0.10", dst: "10.0.0.1", ttl: 64, sport: 40000, dport: 65001, payload: []byte{0xde, 0xad, 0xbe, 0xef}},
		}
		assertICMPQuoteCases(t, pkts, cases)
	})
}

type icmpQuoteCase struct {
	typ, code    uint8
	src, dst     string
	ttl          uint8
	sport, dport uint16
	payload      []byte
}

func assertICMPQuoteCases(t *testing.T, pkts []gopacket.Packet, cases []icmpQuoteCase) {
	t.Helper()
	if len(pkts) != len(cases)*2 {
		t.Fatalf("期望 %d 个包,得到 %d", len(cases)*2, len(pkts))
	}
	for i, tc := range cases {
		assertNoICMP(t, pkts[i*2])
		assertQuotedICMP(t, pkts[i*2+1], tc)
	}
}

func assertNoICMP(t *testing.T, p gopacket.Packet) {
	t.Helper()
	if p.Layer(layers.LayerTypeICMPv4) != nil {
		t.Fatal("触发包不应带 ICMP 层")
	}
}

func assertQuotedICMP(t *testing.T, p gopacket.Packet, want icmpQuoteCase) {
	t.Helper()
	l := p.Layer(layers.LayerTypeICMPv4)
	if l == nil {
		t.Fatal("期望 ICMP 层")
	}
	icmp := l.(*layers.ICMPv4)
	if icmp.TypeCode.Type() != want.typ || icmp.TypeCode.Code() != want.code {
		t.Fatalf("type/code 不符合预期:type=%d code=%d", icmp.TypeCode.Type(), icmp.TypeCode.Code())
	}
	inner := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.Default)
	ipL := inner.Layer(layers.LayerTypeIPv4)
	if ipL == nil {
		t.Fatalf("ICMP payload 未解析出内层 IPv4: %x", icmp.Payload)
	}
	ip := ipL.(*layers.IPv4)
	if ip.SrcIP.String() != want.src || ip.DstIP.String() != want.dst || ip.TTL != want.ttl {
		t.Fatalf("内层 IPv4 不符合预期:src=%s dst=%s ttl=%d", ip.SrcIP, ip.DstIP, ip.TTL)
	}
	udpL := inner.Layer(layers.LayerTypeUDP)
	if udpL == nil {
		t.Fatal("ICMP payload 未解析出内层 UDP")
	}
	udp := udpL.(*layers.UDP)
	if uint16(udp.SrcPort) != want.sport || uint16(udp.DstPort) != want.dport {
		t.Fatalf("内层 UDP 不符合预期:sport=%d dport=%d", udp.SrcPort, udp.DstPort)
	}
	if !bytes.Equal(udp.Payload, want.payload) {
		t.Fatalf("内层 payload 不符合预期: got=%x want=%x", udp.Payload, want.payload)
	}
}

func readICMPPackets(t *testing.T, data []byte) []*layers.ICMPv4 {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	var out []*layers.ICMPv4
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		if l := p.Layer(layers.LayerTypeICMPv4); l != nil {
			out = append(out, l.(*layers.ICMPv4))
		}
	}
	return out
}

func readPackets(t *testing.T, data []byte) []gopacket.Packet {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
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

func TestDNSMultiContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/dns_multi.yaml")
	dnsPackets := readDNSPackets(t, pcap)
	if len(dnsPackets) != 14 {
		t.Fatalf("期望 14 个 DNS 包(7 组 query/response),得到 %d", len(dnsPackets))
	}

	expectDNSPair(t, dnsPackets, 0, layers.DNSTypeA, "example.com", func(rr layers.DNSResourceRecord) {
		if !rr.IP.Equal(net.ParseIP("93.184.216.34")) {
			t.Fatalf("A answer = %v,期望 93.184.216.34", rr.IP)
		}
	})
	expectDNSPair(t, dnsPackets, 2, layers.DNSTypeAAAA, "example.com", func(rr layers.DNSResourceRecord) {
		if !rr.IP.Equal(net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")) {
			t.Fatalf("AAAA answer = %v", rr.IP)
		}
	})
	expectDNSPair(t, dnsPackets, 4, layers.DNSTypeCNAME, "www.example.com", func(rr layers.DNSResourceRecord) {
		if string(rr.CNAME) != "example.com" {
			t.Fatalf("CNAME answer = %q", rr.CNAME)
		}
	})
	expectDNSPair(t, dnsPackets, 6, layers.DNSTypeNS, "example.com", func(rr layers.DNSResourceRecord) {
		if string(rr.NS) != "ns1.example.com" {
			t.Fatalf("NS answer = %q", rr.NS)
		}
	})
	expectDNSPair(t, dnsPackets, 8, layers.DNSTypePTR, "34.216.184.93.in-addr.arpa", func(rr layers.DNSResourceRecord) {
		if string(rr.PTR) != "example.com" {
			t.Fatalf("PTR answer = %q", rr.PTR)
		}
	})
	expectDNSPair(t, dnsPackets, 10, layers.DNSTypeMX, "example.com", func(rr layers.DNSResourceRecord) {
		if rr.MX.Preference != 10 || string(rr.MX.Name) != "mail.example.com" {
			t.Fatalf("MX answer = %#v", rr.MX)
		}
	})
	expectDNSPair(t, dnsPackets, 12, layers.DNSTypeTXT, "example.com", func(rr layers.DNSResourceRecord) {
		if len(rr.TXTs) != 1 || string(rr.TXTs[0]) != "v=spf1 include:_spf.example.com ~all" {
			t.Fatalf("TXT answer = %#v", rr.TXTs)
		}
	})
}

func expectDNSPair(t *testing.T, pkts []*layers.DNS, i int, typ layers.DNSType, qname string, check func(layers.DNSResourceRecord)) {
	t.Helper()
	q := pkts[i]
	if q.QR || len(q.Questions) != 1 || string(q.Questions[0].Name) != qname || q.Questions[0].Type != typ {
		t.Fatalf("包%d 应为 %s 查询 %s,得到 %#v", i, typ, qname, q.Questions)
	}
	r := pkts[i+1]
	if !r.QR || len(r.Answers) != 1 || r.Answers[0].Type != typ {
		t.Fatalf("包%d 应为 %s 响应,得到 %#v", i+1, typ, r.Answers)
	}
	check(r.Answers[0])
}

func readDNSPackets(t *testing.T, data []byte) []*layers.DNS {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	var out []*layers.DNS
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		if l := p.Layer(layers.LayerTypeDNS); l != nil {
			out = append(out, l.(*layers.DNS))
		}
	}
	return out
}

func generatePcap(t *testing.T, path string) []byte {
	t.Helper()
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate %s: %v", path, err)
	}
	for _, f := range s.Flows {
		pkts, err := flow.Expand(f)
		if err != nil {
			t.Fatalf("expand %s: %v", path, err)
		}
		s.Packets = append(s.Packets, pkts...)
	}
	pkts, err := builder.Build(s)
	if err != nil {
		t.Fatalf("build %s: %v", path, err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return buf.Bytes()
}
