package scenario

import (
	"strings"
	"testing"
)

func TestSummarizePackets(t *testing.T) {
	pkts := []Packet{
		{
			Stack: []Layer{
				{Type: "eth"},
				{Type: "ipv4", Fields: &IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp"},
				{Type: "http_request"},
			},
		},
		{
			Stack: []Layer{
				{Type: "eth"},
				{Type: "ipv4", Fields: &IPv4Fields{Src: "10.0.0.2", Dst: "10.0.0.1"}},
				{Type: "tcp"},
			},
		},
		{
			Stack: []Layer{
				{Type: "eth"},
				{Type: "ipv4", Fields: &IPv4Fields{Src: "1.1.1.1", Dst: "2.2.2.2"}},
				{Type: "gre"},
				{Type: "ipv4", Fields: &IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"}},
				{Type: "tcp"},
			},
		},
		{
			Stack: []Layer{
				{Type: "eth"},
				{Type: "payload_hex", Fields: PayloadHex("0xdeadbeef")},
			},
		},
		{
			Stack: []Layer{
				{Type: "eth"},
				{Type: "ipv4", Fields: &IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp"},
				{Type: "payload_hex", Fields: PayloadHex("0x474554")},
			},
			SummaryLayers: []string{"http"},
		},
		{
			Stack: []Layer{
				{Type: "payload"},
				{Type: "tcp_session"},
				{Type: "http_response"},
			},
		},
		{
			Stack: []Layer{
				{Type: "eth"},
				{Type: "ipv6", Fields: &IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2"}},
				{Type: "tcp"},
			},
		},
		{
			Stack: []Layer{
				{Type: "eth"},
				{Type: "ipv6", Fields: &IPv6Fields{Src: "2001:db8::2", Dst: "2001:db8::1"}},
				{Type: "icmpv6"},
			},
		},
	}

	got := SummarizePackets(pkts)
	want := []string{
		"[1] 10.0.0.1 -> 10.0.0.2  eth/ipv4/tcp/http",
		"[2] 10.0.0.1 <- 10.0.0.2  eth/ipv4/tcp",
		"[3] 192.168.1.1 -> 192.168.1.2  eth/ipv4/gre/ipv4/tcp",
		"[4] - -> -  eth",
		"[5] 10.0.0.1 -> 10.0.0.2  eth/ipv4/tcp/http",
		"[6] - -> -  http",
		"[7] 2001:db8::1 -> 2001:db8::2  eth/ipv6/tcp",
		"[8] 2001:db8::2 -> 2001:db8::1  eth/ipv6/icmpv6",
	}
	if len(got) != len(want) {
		t.Fatalf("摘要数量=%d,期望 %d", len(got), len(want))
	}
	for i, w := range want {
		if line := FormatPacketSummary(i+1, got[i]); line != w {
			t.Errorf("第%d行=%q,期望 %q", i+1, line, w)
		}
	}
}

func TestValidateQuoteFromReference(t *testing.T) {
	s := &Scenario{Packets: []Packet{{
		Stack: []Layer{{Type: "icmp", Fields: &ICMPFields{QuoteFrom: "missing"}}},
	}}}
	err := Validate(s)
	if err == nil || !strings.Contains(err.Error(), `quote_from 引用未知 packet "missing"`) {
		t.Fatalf("Validate() error=%v,期望 quote_from 未知引用", err)
	}
}
