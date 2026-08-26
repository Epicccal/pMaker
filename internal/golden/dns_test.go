package golden_test

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

func TestDNSMultiContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/dns/multi.yaml")
	dnsPackets := readDNSPackets(t, pcap)
	if len(dnsPackets) != 18 {
		t.Fatalf("期望 18 个 DNS 包(9 组 query/response),得到 %d", len(dnsPackets))
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
	expectDNSPair(t, dnsPackets, 14, layers.DNSTypeSOA, "example.com", func(rr layers.DNSResourceRecord) {
		soa := rr.SOA
		if string(soa.MName) != "ns1.example.com" || string(soa.RName) != "hostmaster.example.com" {
			t.Fatalf("SOA MName/RName = %q/%q", soa.MName, soa.RName)
		}
		if soa.Serial != 2024010101 || soa.Refresh != 7200 || soa.Retry != 3600 || soa.Expire != 1209600 || soa.Minimum != 3600 {
			t.Fatalf("SOA 数值字段 = serial=%d refresh=%d retry=%d expire=%d minimum=%d",
				soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum)
		}
	})
	expectDNSPair(t, dnsPackets, 16, layers.DNSTypeSRV, "_sip._tcp.example.com", func(rr layers.DNSResourceRecord) {
		srv := rr.SRV
		if srv.Priority != 10 || srv.Weight != 20 || srv.Port != 5060 || string(srv.Name) != "sipserver.example.com" {
			t.Fatalf("SRV answer = priority=%d weight=%d port=%d target=%q",
				srv.Priority, srv.Weight, srv.Port, srv.Name)
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
