package scenario

import (
	"strings"
	"testing"
	"time"
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

// TestValidateSegmentIntervalNeedsMSS: segment.interval 必须配 mss>0,否则整条不切、
// interval 无处生效,会被静默吞掉。validate 应尽早报错。
func TestValidateSegmentIntervalNeedsMSS(t *testing.T) {
	stack := []Layer{
		{Type: "eth", Fields: &EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "tcp", Fields: &TCPFields{SPort: 1111, DPort: 80}},
		{Type: "tcp_session", Fields: &TCPSessionFields{Open: "none", Close: "none"}},
	}
	// 包内测试可直接构造 Offset(校验只看 Interval 指针非 nil,不看 Duration 值)。
	interval := &Offset{}
	msg := func(seg *Segment) Message {
		return Message{From: "src", Stack: []Layer{{Type: "payload_hex", Fields: PayloadHex("0xab")}}, Segment: seg}
	}

	// interval 无 mss → 报错。
	s := &Scenario{Flows: []FlowSpec{{Name: "f", Stack: stack, Messages: []Message{
		msg(&Segment{Interval: interval}), // mss=0
	}}}}
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "interval 需配合 mss>0") {
		t.Fatalf("Validate() error=%v,期望 interval 需配合 mss>0", err)
	}

	// interval + mss>0 → 通过。
	s2 := &Scenario{Flows: []FlowSpec{{Name: "f", Stack: stack, Messages: []Message{
		msg(&Segment{MSS: 8, Interval: interval}),
	}}}}
	if err := Validate(s2); err != nil {
		t.Fatalf("Validate() 有 mss 时不应报错,得到 %v", err)
	}

	// 只 mss 无 interval → 通过。
	s3 := &Scenario{Flows: []FlowSpec{{Name: "f", Stack: stack, Messages: []Message{
		msg(&Segment{MSS: 8}),
	}}}}
	if err := Validate(s3); err != nil {
		t.Fatalf("Validate() 只 mss 不应报错,得到 %v", err)
	}
}

// TestSummarizePlannedWithTime: SummarizePlanned 保留 PlannedPacket.Time,
// FormatPacketSummary 在序号与源 IP 之间输出 ISO8601 时间列;反向包仍归一化为 <-。
func TestSummarizePlannedWithTime(t *testing.T) {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	planned := []PlannedPacket{
		{Packet: Packet{Stack: []Layer{
			{Type: "eth"},
			{Type: "ipv4", Fields: &IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
			{Type: "tcp"},
		}}, Time: base},
		{Packet: Packet{Stack: []Layer{
			{Type: "eth"},
			{Type: "ipv4", Fields: &IPv4Fields{Src: "10.0.0.80", Dst: "10.0.0.10"}},
			{Type: "tcp"},
		}}, Time: base.Add(time.Millisecond)},
	}

	got := SummarizePlanned(planned)
	want := []string{
		"[1] 2020-01-01T00:00:00.000000Z 10.0.0.10 -> 10.0.0.80  eth/ipv4/tcp",
		"[2] 2020-01-01T00:00:00.001000Z 10.0.0.10 <- 10.0.0.80  eth/ipv4/tcp",
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

// TestSummarizePacketsNoTime: SummarizePackets 路径无时间信息,
// FormatPacketSummary 保持不含时间列的原格式(向后兼容)。
func TestSummarizePacketsNoTime(t *testing.T) {
	pkts := []Packet{{
		Stack: []Layer{
			{Type: "eth"},
			{Type: "ipv4", Fields: &IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
			{Type: "tcp"},
		},
	}}
	got := SummarizePackets(pkts)
	if len(got) != 1 {
		t.Fatalf("摘要数量=%d,期望 1", len(got))
	}
	if got[0].HasTime {
		t.Errorf("SummarizePackets 不应带时间信息,得到 HasTime=true")
	}
	want := "[1] 10.0.0.10 -> 10.0.0.80  eth/ipv4/tcp"
	if line := FormatPacketSummary(1, got[0]); line != want {
		t.Errorf("格式=%q,期望 %q", line, want)
	}
}

// TestFormatPacketSummariesAlignsColumns: 多行输出必须跨行对齐——序号位数变化([1] vs [12])、
// IP 长度不一(10.0.0.1 vs 192.168.100.1 vs 无 IP 的 "-")不应让箭头列与协议栈列错位。
// 用列位置而非逐字符比对,直接断言"对齐"这一整表属性,避免脆弱的空格计数。
func TestFormatPacketSummariesAlignsColumns(t *testing.T) {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	// 12 包:序号达两位(idxW=2);混入长 IP 与无 IP 包,制造左/右 IP 宽度差。
	planned := make([]PlannedPacket, 12)
	for i := range planned {
		planned[i] = PlannedPacket{
			Packet: Packet{Stack: []Layer{
				{Type: "eth"},
				{Type: "ipv4", Fields: &IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp"},
			}},
			Time: base.Add(time.Duration(i) * time.Millisecond),
		}
	}
	planned[9].Packet.Stack[1] = Layer{Type: "ipv4", Fields: &IPv4Fields{Src: "192.168.100.1", Dst: "192.168.100.80"}}
	planned[11].Packet.Stack = []Layer{{Type: "eth"}} // 无 IP → "- -> -"

	summaries := SummarizePlanned(planned)
	lines := FormatPacketSummaries(summaries)
	if len(lines) != len(planned) {
		t.Fatalf("行数=%d,期望 %d", len(lines), len(planned))
	}

	// 对齐不变量:每行的 ']'(序号尾)、箭头、协议栈起点三列在所有行落同一位置。
	// stack 右锚于行末,故其起点列 = len(line) - len(stack)。
	var closeCol, arrowCol, stackCol int
	for i, line := range lines {
		cClose := strings.Index(line, "]")
		cArrow := strings.Index(line, "->")
		if cArrow < 0 {
			cArrow = strings.Index(line, "<-")
		}
		cStack := len(line) - len(summaries[i].Stack)
		if i == 0 {
			closeCol, arrowCol, stackCol = cClose, cArrow, cStack
			continue
		}
		if cClose != closeCol {
			t.Errorf("第%d行 ']' 列=%d,首行=%d,序号未对齐", i+1, cClose, closeCol)
		}
		if cArrow != arrowCol {
			t.Errorf("第%d行箭头列=%d,首行=%d,箭头未对齐", i+1, cArrow, arrowCol)
		}
		if cStack != stackCol {
			t.Errorf("第%d行栈列=%d,首行=%d,协议栈未对齐", i+1, cStack, stackCol)
		}
	}

	// 序号本身在两位时应右对齐补空格(无 IP 行序号 12 不补,1 补为 " 1")。
	if lines[0][:4] != "[ 1]" {
		t.Errorf("首行序号=%q,期望 [ 1](两位宽右对齐)", lines[0][:4])
	}
	if lines[11][:4] != "[12]" {
		t.Errorf("末行序号=%q,期望 [12]", lines[11][:4])
	}
}

// TestSummarizeWithPorts: 摘要端点应带上 TCP/UDP 源目端口;反向包端口随方向归一
// (左恒为 base 源端端口、右恒为 base 目的端端口,仅箭头翻转);无 TCP/UDP 层的包不显示端口。
func TestSummarizeWithPorts(t *testing.T) {
	pkts := []Packet{
		// [1] 正向请求:src=client(49152) -> dst=server(80)。base=(client,server)。
		{Stack: []Layer{
			{Type: "eth"},
			{Type: "ipv4", Fields: &IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
			{Type: "tcp", Fields: &TCPFields{SPort: 49152, DPort: 80}},
		}},
		// [2] 反向响应:实际 src=server(80)、dst=client(49152);归一为 client <- server。
		{Stack: []Layer{
			{Type: "eth"},
			{Type: "ipv4", Fields: &IPv4Fields{Src: "10.0.0.80", Dst: "10.0.0.10"}},
			{Type: "tcp", Fields: &TCPFields{SPort: 80, DPort: 49152}},
		}},
		// [3] UDP:端口照样展示。
		{Stack: []Layer{
			{Type: "eth"},
			{Type: "ipv4", Fields: &IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
			{Type: "udp", Fields: &UDPFields{SPort: 5353, DPort: 5353}},
		}},
		// [4] ICMP:无 TCP/UDP 层,端点仅显示 IP,不带端口。
		{Stack: []Layer{
			{Type: "eth"},
			{Type: "ipv4", Fields: &IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
			{Type: "icmp"},
		}},
		// [5] IPv6 + TCP:端口同样拼接。
		{Stack: []Layer{
			{Type: "eth"},
			{Type: "ipv6", Fields: &IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2"}},
			{Type: "tcp", Fields: &TCPFields{SPort: 443, DPort: 443}},
		}},
	}
	got := SummarizePackets(pkts)
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
		if line := FormatPacketSummary(i+1, got[i]); line != w {
			t.Errorf("第%d行=%q,期望 %q", i+1, line, w)
		}
	}
}
