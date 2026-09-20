package summary_test

import (
	"testing"
	"time"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/summary"
)

func TestSummarizePlanned(t *testing.T) {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(i int) time.Time { return base.Add(time.Duration(i) * time.Millisecond) }
	pkt := func(layers ...scenario.Layer) scenario.PlannedPacket {
		return scenario.PlannedPacket{Packet: scenario.Packet{Stack: layers}, Time: at(0)}
	}
	planned := []scenario.PlannedPacket{
		pkt(
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			scenario.Layer{Type: "tcp"},
			scenario.Layer{Type: "http_request"},
		),
		pkt(
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.2", Dst: "10.0.0.1"}},
			scenario.Layer{Type: "tcp"},
		),
		pkt(
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "1.1.1.1", Dst: "2.2.2.2"}},
			scenario.Layer{Type: "gre"},
			scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"}},
			scenario.Layer{Type: "tcp"},
		),
		pkt(
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "payload_hex", Fields: scenario.PayloadHex("0xdeadbeef")},
		),
		{Packet: scenario.Packet{Stack: []scenario.Layer{
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			scenario.Layer{Type: "tcp"},
			scenario.Layer{Type: "payload_hex", Fields: scenario.PayloadHex("0x474554")},
		}, SummaryLayers: []string{"http"}}, Time: at(0)},
		pkt(
			scenario.Layer{Type: "payload"},
			scenario.Layer{Type: "tcp_session"},
			scenario.Layer{Type: "http_response"},
		),
		pkt(
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2"}},
			scenario.Layer{Type: "tcp"},
		),
		pkt(
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::2", Dst: "2001:db8::1"}},
			scenario.Layer{Type: "icmpv6"},
		),
	}

	got := summary.SummarizeOut(planned, outOfPlanned(planned))
	// 逐行断言端点/方向/协议栈(格式化对齐由 format_test.go 单独覆盖)。
	want := []struct{ left, arrow, right, stack string }{
		{"10.0.0.1", "->", "10.0.0.2", "eth/ipv4/tcp/http"},
		{"10.0.0.1", "<-", "10.0.0.2", "eth/ipv4/tcp"},
		{"192.168.1.1", "->", "192.168.1.2", "eth/ipv4/gre/ipv4/tcp"},
		{"-", "->", "-", "eth"},
		{"10.0.0.1", "->", "10.0.0.2", "eth/ipv4/tcp/http"},
		{"-", "->", "-", "http"},
		{"2001:db8::1", "->", "2001:db8::2", "eth/ipv6/tcp"},
		{"2001:db8::2", "->", "2001:db8::1", "eth/ipv6/icmpv6"},
	}
	if len(got) != len(want) {
		t.Fatalf("摘要数量=%d,期望 %d", len(got), len(want))
	}
	for i, w := range want {
		s := got[i]
		if s.Left != w.left || s.Arrow != w.arrow || s.Right != w.right || s.Stack != w.stack {
			t.Errorf("第%d行=%v,期望 %v", i+1, s, w)
		}
	}
}

// TestSummarizePlannedWithTime: SummarizePlanned 保留 PlannedPacket.Time,
// FormatPacketSummaries 在序号与源 IP 之间输出 ISO8601 时间列;反向包仍归一化为 <-。
func TestSummarizePlannedWithTime(t *testing.T) {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	planned := []scenario.PlannedPacket{
		{Packet: scenario.Packet{Stack: []scenario.Layer{
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
			scenario.Layer{Type: "tcp"},
		}}, Time: base},
		{Packet: scenario.Packet{Stack: []scenario.Layer{
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.80", Dst: "10.0.0.10"}},
			scenario.Layer{Type: "tcp"},
		}}, Time: base.Add(time.Millisecond)},
	}

	got := summary.SummarizeOut(planned, outOfPlanned(planned))
	lines := summary.FormatPacketSummaries(got)
	want := []string{
		"[1] 2020-01-01T00:00:00.000000Z 10.0.0.10 -> 10.0.0.80  eth/ipv4/tcp",
		"[2] 2020-01-01T00:00:00.001000Z 10.0.0.10 <- 10.0.0.80  eth/ipv4/tcp",
	}
	if len(lines) != len(want) {
		t.Fatalf("行数=%d,期望 %d", len(lines), len(want))
	}
	for i, w := range want {
		if lines[i] != w {
			t.Errorf("第%d行=%q,期望 %q", i+1, lines[i], w)
		}
	}
}

// TestSummarizeUDPFlowPackets: UDP flow 展开包(udp_session 会话,端口在反向包被交换)
// 的摘要端口显示与方向归一 —— 左恒为 base 源端(客户端),箭头随方向翻转。
func TestSummarizeUDPFlowPackets(t *testing.T) {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	pkt := func(layers ...scenario.Layer) scenario.PlannedPacket {
		return scenario.PlannedPacket{Packet: scenario.Packet{Stack: layers}, Time: base}
	}
	planned := []scenario.PlannedPacket{
		// [1] 正向查询:client(49152) -> server(53)。base=(client,server)。
		pkt(
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.53"}},
			scenario.Layer{Type: "udp", Fields: &scenario.UDPFields{SPort: 49152, DPort: 53}},
			scenario.Layer{Type: "payload_hex", Fields: scenario.PayloadHex("0x71")},
		),
		// [2] 反向应答:展开器交换端口,实际 53 -> 49152;归一为 client <- server。
		pkt(
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.53", Dst: "10.0.0.10"}},
			scenario.Layer{Type: "udp", Fields: &scenario.UDPFields{SPort: 53, DPort: 49152}},
			scenario.Layer{Type: "payload_hex", Fields: scenario.PayloadHex("0x61")},
		),
	}
	got := summary.SummarizeOut(planned, outOfPlanned(planned))
	want := []struct{ left, arrow, right, stack string }{
		{"10.0.0.10:49152", "->", "10.0.0.53:53", "eth/ipv4/udp"},
		{"10.0.0.10:49152", "<-", "10.0.0.53:53", "eth/ipv4/udp"},
	}
	if len(got) != len(want) {
		t.Fatalf("摘要数量=%d,期望 %d", len(got), len(want))
	}
	for i, w := range want {
		s := got[i]
		if s.Left != w.left || s.Arrow != w.arrow || s.Right != w.right || s.Stack != w.stack {
			t.Errorf("第%d行=%v,期望 {left:%s arrow:%s right:%s stack:%s}", i+1, s, w.left, w.arrow, w.right, w.stack)
		}
	}
}

// TestSummarizeWithPorts: 摘要端点应带上 TCP/UDP 源目端口;反向包端口随方向归一
// (左恒为 base 源端端口、右恒为 base 目的端端口,仅箭头翻转);无 TCP/UDP 层的包不显示端口。
func TestSummarizeWithPorts(t *testing.T) {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	pkt := func(layers ...scenario.Layer) scenario.PlannedPacket {
		return scenario.PlannedPacket{Packet: scenario.Packet{Stack: layers}, Time: base}
	}
	planned := []scenario.PlannedPacket{
		// [1] 正向请求:src=client(49152) -> dst=server(80)。base=(client,server)。
		pkt(
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
			scenario.Layer{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 80}},
		),
		// [2] 反向响应:实际 src=server(80)、dst=client(49152);归一为 client <- server。
		pkt(
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.80", Dst: "10.0.0.10"}},
			scenario.Layer{Type: "tcp", Fields: &scenario.TCPFields{SPort: 80, DPort: 49152}},
		),
		// [3] UDP:端口照样展示。
		pkt(
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
			scenario.Layer{Type: "udp", Fields: &scenario.UDPFields{SPort: 5353, DPort: 5353}},
		),
		// [4] ICMP:无 TCP/UDP 层,端点仅显示 IP,不带端口。
		pkt(
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
			scenario.Layer{Type: "icmp"},
		),
		// [5] IPv6 + TCP:端口同样拼接。
		pkt(
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2"}},
			scenario.Layer{Type: "tcp", Fields: &scenario.TCPFields{SPort: 443, DPort: 443}},
		),
	}
	got := summary.SummarizeOut(planned, outOfPlanned(planned))
	// 逐行断言端点(格式化对齐由 format_test.go 单独覆盖):端口随方向归一,左恒为 base 源端。
	want := []struct{ left, arrow, right string }{
		{"10.0.0.10:49152", "->", "10.0.0.80:80"},
		{"10.0.0.10:49152", "<-", "10.0.0.80:80"},
		{"10.0.0.10:5353", "->", "10.0.0.80:5353"},
		{"10.0.0.10", "->", "10.0.0.80"},
		{"[2001:db8::1]:443", "->", "[2001:db8::2]:443"},
	}
	if len(got) != len(want) {
		t.Fatalf("摘要数量=%d,期望 %d", len(got), len(want))
	}
	for i, w := range want {
		s := got[i]
		if s.Left != w.left || s.Arrow != w.arrow || s.Right != w.right {
			t.Errorf("第%d行端点=%q %s %q,期望 %q %s %q", i+1, s.Left, s.Arrow, s.Right, w.left, w.arrow, w.right)
		}
	}
}

// TestSummarizeOutFragments: SummarizeOut 按片展开分片包 —— N 片产 N 行,Stack 列
// 附 " frag k/N"(k 从 1 计),各片时间与原包同刻;未分片包不附 frag 标记。
func TestSummarizeOutFragments(t *testing.T) {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	planned := []scenario.PlannedPacket{
		{Packet: scenario.Packet{Stack: []scenario.Layer{
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			scenario.Layer{Type: "udp"},
		}}, Time: base},
		{Packet: scenario.Packet{Stack: []scenario.Layer{
			scenario.Layer{Type: "eth"},
			scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			scenario.Layer{Type: "udp"},
		}}, Time: base},
	}
	pkts := []builder.OutPacket{
		{Data: []byte{1}, Time: base, Frag: builder.FragInfo{PlannedIdx: 0, K: 0, N: 3}},
		{Data: []byte{2}, Time: base, Frag: builder.FragInfo{PlannedIdx: 0, K: 1, N: 3}},
		{Data: []byte{3}, Time: base, Frag: builder.FragInfo{PlannedIdx: 0, K: 2, N: 3}},
		{Data: []byte{4}, Time: base, Frag: builder.FragInfo{PlannedIdx: 1, K: 0, N: 1}},
	}

	got := summary.SummarizeOut(planned, pkts)
	if len(got) != len(pkts) {
		t.Fatalf("摘要行数=%d,期望 %d(分片按片展开)", len(got), len(pkts))
	}
	wantStack := []string{
		"eth/ipv4/udp frag 1/3",
		"eth/ipv4/udp frag 2/3",
		"eth/ipv4/udp frag 3/3",
		"eth/ipv4/udp",
	}
	for i, w := range wantStack {
		if got[i].Stack != w {
			t.Errorf("第%d行 Stack=%q,期望 %q", i+1, got[i].Stack, w)
		}
	}
	if !got[0].Time.Equal(base) {
		t.Fatalf("分片行时间应取 OutPacket.Time(与原包同刻)")
	}
}
