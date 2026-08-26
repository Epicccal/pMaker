package summary_test

import (
	"testing"
	"time"

	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/summary"
)

func TestSummarizePackets(t *testing.T) {
	pkts := []scenario.Packet{
		{
			Stack: []scenario.Layer{
				{Type: "eth"},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp"},
				{Type: "http_request"},
			},
		},
		{
			Stack: []scenario.Layer{
				{Type: "eth"},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.2", Dst: "10.0.0.1"}},
				{Type: "tcp"},
			},
		},
		{
			Stack: []scenario.Layer{
				{Type: "eth"},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "1.1.1.1", Dst: "2.2.2.2"}},
				{Type: "gre"},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"}},
				{Type: "tcp"},
			},
		},
		{
			Stack: []scenario.Layer{
				{Type: "eth"},
				{Type: "payload_hex", Fields: scenario.PayloadHex("0xdeadbeef")},
			},
		},
		{
			Stack: []scenario.Layer{
				{Type: "eth"},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp"},
				{Type: "payload_hex", Fields: scenario.PayloadHex("0x474554")},
			},
			SummaryLayers: []string{"http"},
		},
		{
			Stack: []scenario.Layer{
				{Type: "payload"},
				{Type: "tcp_session"},
				{Type: "http_response"},
			},
		},
		{
			Stack: []scenario.Layer{
				{Type: "eth"},
				{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2"}},
				{Type: "tcp"},
			},
		},
		{
			Stack: []scenario.Layer{
				{Type: "eth"},
				{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::2", Dst: "2001:db8::1"}},
				{Type: "icmpv6"},
			},
		},
	}

	got := summary.SummarizePackets(pkts)
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
		if line := summary.FormatPacketSummary(i+1, got[i]); line != w {
			t.Errorf("第%d行=%q,期望 %q", i+1, line, w)
		}
	}
}

// TestSummarizePlannedWithTime: SummarizePlanned 保留 PlannedPacket.Time,
// FormatPacketSummary 在序号与源 IP 之间输出 ISO8601 时间列;反向包仍归一化为 <-。
func TestSummarizePlannedWithTime(t *testing.T) {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	planned := []scenario.PlannedPacket{
		{Packet: scenario.Packet{Stack: []scenario.Layer{
			{Type: "eth"},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
			{Type: "tcp"},
		}}, Time: base},
		{Packet: scenario.Packet{Stack: []scenario.Layer{
			{Type: "eth"},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.80", Dst: "10.0.0.10"}},
			{Type: "tcp"},
		}}, Time: base.Add(time.Millisecond)},
	}

	got := summary.SummarizePlanned(planned)
	want := []string{
		"[1] 2020-01-01T00:00:00.000000Z 10.0.0.10 -> 10.0.0.80  eth/ipv4/tcp",
		"[2] 2020-01-01T00:00:00.001000Z 10.0.0.10 <- 10.0.0.80  eth/ipv4/tcp",
	}
	if len(got) != len(want) {
		t.Fatalf("摘要数量=%d,期望 %d", len(got), len(want))
	}
	for i, w := range want {
		if line := summary.FormatPacketSummary(i+1, got[i]); line != w {
			t.Errorf("第%d行=%q,期望 %q", i+1, line, w)
		}
	}
}

// TestSummarizePacketsNoTime: SummarizePackets 路径无时间信息,
// FormatPacketSummary 保持不含时间列的原格式(向后兼容)。
func TestSummarizePacketsNoTime(t *testing.T) {
	pkts := []scenario.Packet{{
		Stack: []scenario.Layer{
			{Type: "eth"},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
			{Type: "tcp"},
		},
	}}
	got := summary.SummarizePackets(pkts)
	if len(got) != 1 {
		t.Fatalf("摘要数量=%d,期望 1", len(got))
	}
	if got[0].HasTime {
		t.Errorf("SummarizePackets 不应带时间信息,得到 HasTime=true")
	}
	want := "[1] 10.0.0.10 -> 10.0.0.80  eth/ipv4/tcp"
	if line := summary.FormatPacketSummary(1, got[0]); line != want {
		t.Errorf("格式=%q,期望 %q", line, want)
	}
}

// TestSummarizeWithPorts: 摘要端点应带上 TCP/UDP 源目端口;反向包端口随方向归一
// (左恒为 base 源端端口、右恒为 base 目的端端口,仅箭头翻转);无 TCP/UDP 层的包不显示端口。
func TestSummarizeWithPorts(t *testing.T) {
	pkts := []scenario.Packet{
		// [1] 正向请求:src=client(49152) -> dst=server(80)。base=(client,server)。
		{Stack: []scenario.Layer{
			{Type: "eth"},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 80}},
		}},
		// [2] 反向响应:实际 src=server(80)、dst=client(49152);归一为 client <- server。
		{Stack: []scenario.Layer{
			{Type: "eth"},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.80", Dst: "10.0.0.10"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 80, DPort: 49152}},
		}},
		// [3] UDP:端口照样展示。
		{Stack: []scenario.Layer{
			{Type: "eth"},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
			{Type: "udp", Fields: &scenario.UDPFields{SPort: 5353, DPort: 5353}},
		}},
		// [4] ICMP:无 TCP/UDP 层,端点仅显示 IP,不带端口。
		{Stack: []scenario.Layer{
			{Type: "eth"},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
			{Type: "icmp"},
		}},
		// [5] IPv6 + TCP:端口同样拼接。
		{Stack: []scenario.Layer{
			{Type: "eth"},
			{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 443, DPort: 443}},
		}},
	}
	got := summary.SummarizePackets(pkts)
	want := []string{
		"[1] 10.0.0.10:49152 -> 10.0.0.80:80  eth/ipv4/tcp",
		"[2] 10.0.0.10:49152 <- 10.0.0.80:80  eth/ipv4/tcp",
		"[3] 10.0.0.10:5353 -> 10.0.0.80:5353  eth/ipv4/udp",
		"[4] 10.0.0.10 -> 10.0.0.80  eth/ipv4/icmp",
		"[5] [2001:db8::1]:443 -> [2001:db8::2]:443  eth/ipv6/tcp",
	}
	if len(got) != len(want) {
		t.Fatalf("摘要数量=%d,期望 %d", len(got), len(want))
	}
	for i, w := range want {
		if line := summary.FormatPacketSummary(i+1, got[i]); line != w {
			t.Errorf("第%d行=%q,期望 %q", i+1, line, w)
		}
	}
}
