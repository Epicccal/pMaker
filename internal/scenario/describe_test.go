package scenario

import "testing"

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
	}

	got := SummarizePackets(pkts)
	want := []string{
		"[1] 10.0.0.1 -> 10.0.0.2  eth/ipv4/tcp/http",
		"[2] 10.0.0.1 <- 10.0.0.2  eth/ipv4/tcp",
		"[3] 192.168.1.1 -> 192.168.1.2  eth/ipv4/gre/ipv4/tcp",
		"[4] - -> -  eth",
		"[5] 10.0.0.1 -> 10.0.0.2  eth/ipv4/tcp/http",
		"[6] - -> -  http",
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
