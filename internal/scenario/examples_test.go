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
