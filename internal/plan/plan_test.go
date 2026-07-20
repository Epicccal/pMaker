package plan_test

import (
	"encoding/hex"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// baseFlow 构造一条 open/close 均为 none、单条 payload 消息的流,展开为 2 个 stack 包
// (1 数据段 + 1 对端 ACK),便于在测试里精确定位时间。
func baseFlow(name string, offset *scenario.Offset) scenario.FlowSpec {
	return scenario.FlowSpec{
		Name:       name,
		OffsetTime: offset,
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80, ClientISN: 100, ServerISN: 200}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "none", Close: "none"}},
		},
		Messages: []scenario.Message{{
			From: "src",
			Stack: []scenario.Layer{{
				Type:   "payload_hex",
				Fields: scenario.PayloadHex("0x" + hex.EncodeToString([]byte("hi"))),
			}},
		}},
	}
}

func udpPacket(name string, offset *scenario.Offset) scenario.Packet {
	return scenario.Packet{
		Name:       name,
		OffsetTime: offset,
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "udp", Fields: &scenario.UDPFields{SPort: 5000, DPort: 53}},
			{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}},
		},
	}
}

func times(planned []scenario.PlannedPacket) []time.Time {
	out := make([]time.Time, len(planned))
	for i, pp := range planned {
		out[i] = pp.Time
	}
	return out
}

// TestPlanDefaultPacketsTiming: 未显式定时时,base+i*ms,顺序不变。
func TestPlanDefaultPacketsTiming(t *testing.T) {
	s := &scenario.Scenario{
		Packets: []scenario.Packet{udpPacket("a", nil), udpPacket("b", nil), udpPacket("c", nil)},
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	base := plan.DefaultBaseTime()
	want := []time.Time{base, base.Add(time.Millisecond), base.Add(2 * time.Millisecond)}
	got := times(planned)
	if !equalTimes(got, want) {
		t.Fatalf("默认时间=%v,期望 %v", got, want)
	}
}

// TestPlanDefaultFlowTiming: 无 offset_time 的 flow 包接续默认序列 base+i*ms(回归旧 builder 语义)。
func TestPlanDefaultFlowTiming(t *testing.T) {
	s := &scenario.Scenario{Flows: []scenario.FlowSpec{baseFlow("f", nil)}}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(planned) != 2 {
		t.Fatalf("期望 2 个包,得到 %d", len(planned))
	}
	base := plan.DefaultBaseTime()
	want := []time.Time{base, base.Add(time.Millisecond)}
	if !equalTimes(times(planned), want) {
		t.Fatalf("flow 默认时间=%v,期望 %v", times(planned), want)
	}
}

// TestPlanExplicitPacketOffset: packet.offset_time 相对上一包(第一包相对 base)。
// late(+10s) 先声明 → @base+10s(第一包,相对 base);early(+5ms) 后声明 → late+5ms = base+10.005s
// (相对上一包 late,不再是相对 base 的 5ms)。
func TestPlanExplicitPacketOffset(t *testing.T) {
	base := mustAbs(t, "2024-01-01T00:00:00Z")
	s := &scenario.Scenario{
		BaseTime: base,
		Packets: []scenario.Packet{
			udpPacket("late", mustOffset(t, "+10s")),
			udpPacket("early", mustOffset(t, "+5ms")),
		},
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	origin := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// late@10s(第一包,相对 base);early = late + 5ms = 10.005s(相对上一包)。
	want := []time.Time{origin.Add(10 * time.Second), origin.Add(10*time.Second + 5*time.Millisecond)}
	if !equalTimes(times(planned), want) {
		t.Fatalf("显式时间=%v,期望 %v", times(planned), want)
	}
	if planned[0].Name != "late" || planned[1].Name != "early" {
		t.Fatalf("排序后 name 顺序=%v,期望 [late early]", names(planned))
	}
}

// TestPlanFlowOffsetAnchor: flow.offset_time 把流锚定到 base+offset,流内每包 1ms 间隔。
func TestPlanFlowOffsetAnchor(t *testing.T) {
	s := &scenario.Scenario{
		BaseTime: mustAbs(t, "2024-01-01T00:00:00Z"),
		Flows:    []scenario.FlowSpec{baseFlow("f", mustOffset(t, "+10ms"))},
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	want := []time.Time{base.Add(10 * time.Millisecond), base.Add(11 * time.Millisecond)}
	if !equalTimes(times(planned), want) {
		t.Fatalf("flow offset 锚定时间=%v,期望 %v", times(planned), want)
	}
}

// TestPlanMergeAndSort: packet 与 flow 跨流独立——packet @+30ms,flow @+0ms 在 base 起步
// (不被 packet 拖到 30ms 之后)。按 Time 排序后:flow@base、flow-ack@1ms、late@30ms。
func TestPlanMergeAndSort(t *testing.T) {
	s := &scenario.Scenario{
		BaseTime: mustAbs(t, "2024-01-01T00:00:00Z"),
		Packets:  []scenario.Packet{udpPacket("late", mustOffset(t, "+30ms"))},
		Flows:    []scenario.FlowSpec{baseFlow("quick", mustOffset(t, "+0ms"))},
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// 声明序:late(30ms)、flow(0ms,1ms);排序后应为 flow@0ms、flow-ack@1ms、late@30ms。
	if len(planned) != 3 {
		t.Fatalf("期望 3 个包,得到 %d", len(planned))
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	want := []time.Time{base, base.Add(time.Millisecond), base.Add(30 * time.Millisecond)}
	if !equalTimes(times(planned), want) {
		t.Fatalf("交织排序时间=%v,期望 %v", times(planned), want)
	}
	if planned[0].Name != "" {
		t.Errorf("排序后首个包应为 flow 包(无名),得到 name=%q", planned[0].Name)
	}
	if planned[2].Name != "late" {
		t.Errorf("排序后末包应为 late,得到 name=%q", planned[2].Name)
	}
}

// TestPlanStableSortForEqualTimes: 无 offset 多 flow 在 base 并发——同 Time 的包保持声明/合并
// 顺序(稳定排序保证确定性)。f1、f2 均无 offset,各自 data@base / ack@base+1ms;排序后
// base 处 f1.data 先于 f2.data(声明序),base+1ms 处 f1.ack 先于 f2.ack。
func TestPlanStableSortForEqualTimes(t *testing.T) {
	mkFlow := func(name string, sport uint16) scenario.FlowSpec {
		return scenario.FlowSpec{
			Name: name,
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: sport, DPort: 80, ClientISN: 100, ServerISN: 200}},
				{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "none", Close: "none"}},
			},
			Messages: []scenario.Message{{
				From:  "src",
				Stack: []scenario.Layer{{Type: "payload_hex", Fields: scenario.PayloadHex("0xab")}},
			}},
		}
	}
	s := &scenario.Scenario{
		Flows: []scenario.FlowSpec{mkFlow("f1", 1111), mkFlow("f2", 2222)},
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(planned) != 4 {
		t.Fatalf("期望 4 个包,得到 %d", len(planned))
	}
	base := plan.DefaultBaseTime()
	// 两 flow 并发:base 各 1 个、base+1ms 各 1 个。
	wantTimes := []time.Time{base, base, base.Add(time.Millisecond), base.Add(time.Millisecond)}
	if !equalTimes(times(planned), wantTimes) {
		t.Fatalf("并发同时间=%v,期望 %v", times(planned), wantTimes)
	}
	// 同 Time 保持声明序:f1(端口 1111)在前、f2(端口 2222)在后。data 方向 sport=自身端口;
	// 对端 ACK 反转方向,故看 dport=自身端口。(sport,dport) 唯一标识每条 flow 的包。
	type pair struct{ sport, dport uint16 }
	wantPorts := []pair{{1111, 80}, {2222, 80}, {80, 1111}, {80, 2222}}
	for i, w := range wantPorts {
		sp, dp := tcpPorts(planned[i])
		if sp != w.sport || dp != w.dport {
			t.Fatalf("包%d (sport,dport)=(%d,%d),期望 (%d,%d)(同 Time 稳定性被破坏)", i, sp, dp, w.sport, w.dport)
		}
	}
}

// TestPlanDeterministic: 同一输入两次 Plan 结果完全一致。
func TestPlanDeterministic(t *testing.T) {
	mk := func() *scenario.Scenario {
		return &scenario.Scenario{
			BaseTime: mustAbs(t, "2024-01-01T00:00:00Z"),
			Packets:  []scenario.Packet{udpPacket("late", mustOffset(t, "+30ms"))},
			Flows:    []scenario.FlowSpec{baseFlow("quick", mustOffset(t, "+0ms"))},
		}
	}
	a, err := plan.Plan(mk())
	if err != nil {
		t.Fatalf("Plan a: %v", err)
	}
	b, err := plan.Plan(mk())
	if err != nil {
		t.Fatalf("Plan b: %v", err)
	}
	if len(a) != len(b) {
		t.Fatalf("两次 Plan 长度不同 %d/%d", len(a), len(b))
	}
	for i := range a {
		if !a[i].Time.Equal(b[i].Time) || a[i].Name != b[i].Name {
			t.Fatalf("两次 Plan 第%d包不一致: %+v vs %+v", i, a[i], b[i])
		}
	}
}

// TestAbsTimeRejectsOffset: AbsTime 只解析 ISO8601,偏移字符串直接失败(结构性保证)。
func TestAbsTimeRejectsOffset(t *testing.T) {
	a := &scenario.AbsTime{}
	if err := yaml.Unmarshal([]byte("+1s"), a); err == nil {
		t.Fatal("期望 AbsTime 拒绝偏移字符串,实际通过")
	}
}

// TestOffsetRejectsAbsolute: Offset 只解析时长,绝对时刻直接失败(结构性保证)。
func TestOffsetRejectsAbsolute(t *testing.T) {
	o := &scenario.Offset{}
	if err := yaml.Unmarshal([]byte("2024-01-01T00:00:00Z"), o); err == nil {
		t.Fatal("期望 Offset 拒绝绝对时刻字符串,实际通过")
	}
}

// TestOffsetRejectsNegative: Offset 拒绝负时长——负偏移通常意味着 base_time 选错起点,
// 应把 base_time 提前而非用负 offset 够到零点之前(结构性保证)。
func TestOffsetRejectsNegative(t *testing.T) {
	for _, s := range []string{"-1ms", "-1.5s", "-500ms"} {
		o := &scenario.Offset{}
		if err := yaml.Unmarshal([]byte(s), o); err == nil {
			t.Fatalf("期望 Offset 拒绝负时长 %q,实际通过", s)
		}
	}
	// 0 与正值仍应通过。
	for _, s := range []string{"0s", "+0ms", "+1.5s", "500ms"} {
		o := &scenario.Offset{}
		if err := yaml.Unmarshal([]byte(s), o); err != nil {
			t.Fatalf("期望 Offset 接受非负时长 %q,实际失败: %v", s, err)
		}
	}
}

func names(planned []scenario.PlannedPacket) []string {
	out := make([]string, len(planned))
	for i, pp := range planned {
		out[i] = pp.Name
	}
	return out
}

// tcpPorts 从 PlannedPacket 的层栈中提取 TCP 源/目的端口(用于区分并发 flow 的同 Time 包;
// 对端 ACK 反转方向,故需同时看 sport/dport)。
func tcpPorts(pp scenario.PlannedPacket) (sport, dport uint16) {
	for _, l := range pp.Stack {
		if tcp, ok := l.Fields.(*scenario.TCPFields); ok {
			return tcp.SPort, tcp.DPort
		}
	}
	return 0, 0
}

func equalTimes(a, b []time.Time) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

// mustAbs 经 YAML 解析路径把 ISO8601 字符串解析为 AbsTime,失败即 Fatal。
func mustAbs(t *testing.T, s string) *scenario.AbsTime {
	t.Helper()
	a := &scenario.AbsTime{}
	if err := yaml.Unmarshal([]byte(s), a); err != nil {
		t.Fatalf("解析 base_time %q: %v", s, err)
	}
	return a
}

// mustOffset 经 YAML 解析路径把时长字符串解析为 Offset,失败即 Fatal。
func mustOffset(t *testing.T, s string) *scenario.Offset {
	t.Helper()
	o := &scenario.Offset{}
	if err := yaml.Unmarshal([]byte(s), o); err != nil {
		t.Fatalf("解析 offset %q: %v", s, err)
	}
	return o
}

// noneStack 返回 open=none/close=none 的最小 TCP 会话栈,供时间测试复用。
func noneStack() []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80, ClientISN: 100, ServerISN: 200}},
		{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "none", Close: "none"}},
	}
}

// handshakeStack 返回 open=handshake/close=none 的栈:握手占 anchor 起 3×DefaultStep,
// 用于验证 message.offset_time 的零点是"握手完成后"而非流锚。
func handshakeStack() []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80, ClientISN: 100, ServerISN: 200}},
		{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "none"}},
	}
}

// ph 构造一个 payload_hex 层。
func ph(hex string) scenario.Layer {
	return scenario.Layer{Type: "payload_hex", Fields: scenario.PayloadHex(hex)}
}

// TestPlanMessageOffset: message.offset_time 把该消息整组锚定到 anchor+offset(相对流起始锚)。
// flow 无 offset → anchor=base;message +50ms → 数据段与 ACK 落在 base+50ms / base+51ms。
func TestPlanMessageOffset(t *testing.T) {
	s := &scenario.Scenario{
		BaseTime: mustAbs(t, "2024-01-01T00:00:00Z"),
		Flows: []scenario.FlowSpec{{
			Name:  "f",
			Stack: noneStack(),
			Messages: []scenario.Message{{
				From:       "src",
				OffsetTime: mustOffset(t, "+50ms"),
				Stack:      []scenario.Layer{ph("0xab")},
			}},
		}},
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	want := []time.Time{base.Add(50 * time.Millisecond), base.Add(51 * time.Millisecond)}
	if !equalTimes(times(planned), want) {
		t.Fatalf("message offset 时间=%v,期望 %v", times(planned), want)
	}
}

// TestPlanMessageOffsetAfterHandshake: open=handshake 时,message.offset_time 的零点是
// "握手完成后"而非流锚。握手占 base+0/1/2ms,message +50ms → 数据段在 base+3ms+50ms=53ms,
// ACK 在 54ms。若误把零点当流锚,数据段会落在 50ms(与握手 ACK@2ms 之间,且早于预期)。
func TestPlanMessageOffsetAfterHandshake(t *testing.T) {
	s := &scenario.Scenario{
		BaseTime: mustAbs(t, "2024-01-01T00:00:00Z"),
		Flows: []scenario.FlowSpec{{
			Name:  "f",
			Stack: handshakeStack(),
			Messages: []scenario.Message{{
				From:       "src",
				OffsetTime: mustOffset(t, "+50ms"),
				Stack:      []scenario.Layer{ph("0xab")},
			}},
		}},
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(planned) != 5 { // 握手 3 + 数据 1 + ACK 1
		t.Fatalf("期望 5 个包,得到 %d", len(planned))
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// 排序后:握手 0/1/2ms,数据 53ms(握手 3ms + offset 50ms),ACK 54ms。
	want := []time.Time{
		base, base.Add(time.Millisecond), base.Add(2 * time.Millisecond),
		base.Add(53 * time.Millisecond), base.Add(54 * time.Millisecond),
	}
	if !equalTimes(times(planned), want) {
		t.Fatalf("握手后锚定时间=%v,期望 %v", times(planned), want)
	}
}

// TestPlanMessageOffsetRelativeAnchor: message.offset_time 相对流锚(anchor=base+flow.offset_time),
// 不是相对 base。flow +1s + message +50ms → base+1050ms / base+1051ms。
func TestPlanMessageOffsetRelativeAnchor(t *testing.T) {
	s := &scenario.Scenario{
		BaseTime: mustAbs(t, "2024-01-01T00:00:00Z"),
		Flows: []scenario.FlowSpec{{
			Name:       "f",
			OffsetTime: mustOffset(t, "+1s"),
			Stack:      noneStack(),
			Messages: []scenario.Message{{
				From:       "src",
				OffsetTime: mustOffset(t, "+50ms"),
				Stack:      []scenario.Layer{ph("0xab")},
			}},
		}},
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	want := []time.Time{base.Add(1050 * time.Millisecond), base.Add(1051 * time.Millisecond)}
	if !equalTimes(times(planned), want) {
		t.Fatalf("相对流锚时间=%v,期望 %v", times(planned), want)
	}
}

// TestPlanSegmentInterval: segment.interval 只作用于数据段;对端 ACK 用 DefaultStep,
// 不被数据段节奏传染。20 字节按 mss=8 切 3 段(8/8/4),interval=+10ms;
// 段在 base/10/20ms,对端 ACK 紧跟最后一段 +1ms = 21ms。
func TestPlanSegmentInterval(t *testing.T) {
	s := &scenario.Scenario{
		BaseTime: mustAbs(t, "2024-01-01T00:00:00Z"),
		Flows: []scenario.FlowSpec{{
			Name:  "f",
			Stack: noneStack(),
			Messages: []scenario.Message{{
				From:    "src",
				Segment: &scenario.Segment{MSS: 8, Interval: mustOffset(t, "+10ms")},
				Stack:   []scenario.Layer{ph("0x" + hex.EncodeToString(make([]byte, 20)))},
			}},
		}},
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(planned) != 4 { // 3 段 + 1 ACK
		t.Fatalf("期望 4 个包,得到 %d", len(planned))
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	want := []time.Time{base, base.Add(10 * time.Millisecond), base.Add(20 * time.Millisecond), base.Add(21 * time.Millisecond)}
	if !equalTimes(times(planned), want) {
		t.Fatalf("segment interval 时间=%v,期望 %v", times(planned), want)
	}
}

// TestPlanMessageOffsetNoHijack: 流内链式——带 offset 的消息相对上一条末尾,后续无 offset 消息
// 紧接其后(正常非流水线 HTTP:慢响应拖慢下一条请求)。
// A(src,无 offset,快)@0/1ms,末尾 2ms;B(dst,offset=+50ms)相对 A 末尾 → 2ms+50ms=52ms,
// @52/53ms,末尾 54ms;C(src,无 offset)紧接 B → @54/55ms。
func TestPlanMessageOffsetNoHijack(t *testing.T) {
	s := &scenario.Scenario{
		BaseTime: mustAbs(t, "2024-01-01T00:00:00Z"),
		Flows: []scenario.FlowSpec{{
			Name:  "f",
			Stack: noneStack(),
			Messages: []scenario.Message{
				{From: "src", Stack: []scenario.Layer{ph("0xaa")}},
				{From: "dst", OffsetTime: mustOffset(t, "+50ms"), Stack: []scenario.Layer{ph("0xbb")}},
				{From: "src", Stack: []scenario.Layer{ph("0xcc")}},
			},
		}},
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(planned) != 6 { // A:data+ack=2, B:data+ack=2, C:data+ack=2
		t.Fatalf("期望 6 个包,得到 %d", len(planned))
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// A.data@0, A.ack@1;B = A 末尾(2ms)+50ms = 52ms,B.data@52, B.ack@53;C 紧接 B 末尾(54ms)@54/55。
	want := []time.Time{
		base, base.Add(time.Millisecond),
		base.Add(52 * time.Millisecond), base.Add(53 * time.Millisecond),
		base.Add(54 * time.Millisecond), base.Add(55 * time.Millisecond),
	}
	if !equalTimes(times(planned), want) {
		t.Fatalf("链式接续时间=%v,期望 %v", times(planned), want)
	}
	// 关键断言:C 的两个包(54/55ms)排在 B(52/53ms)之后——B 的 offset 相对 A 末尾,C 紧接 B 而非接 A。
	if !planned[4].Time.After(planned[2].Time) {
		t.Errorf("C.data(%v) 应在 B.data(%v) 之后", planned[4].Time, planned[2].Time)
	}
}

// TestPlanMessageOffsetChained: message.offset_time 相对上一条消息末尾(链式 delta,非单调也无需夹紧)。
// A(+50ms) 第一条,相对 msgAnchor(base)→ @50/51ms,末尾 52ms;B(+10ms) 相对 A 末尾 → 52ms+10ms=62ms,
// @62/63ms。即便 B 的 offset(10ms)小于 A 的(50ms),也只表示"B 距 A 末尾 10ms",不夹紧、不乱序。
func TestPlanMessageOffsetChained(t *testing.T) {
	s := &scenario.Scenario{
		BaseTime: mustAbs(t, "2024-01-01T00:00:00Z"),
		Flows: []scenario.FlowSpec{{
			Name:  "f",
			Stack: noneStack(),
			Messages: []scenario.Message{
				{From: "src", OffsetTime: mustOffset(t, "+50ms"), Stack: []scenario.Layer{ph("0xab")}},
				{From: "dst", OffsetTime: mustOffset(t, "+10ms"), Stack: []scenario.Layer{ph("0xcd")}},
			},
		}},
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(planned) != 4 { // 各 1 段 + 1 ACK
		t.Fatalf("期望 4 个包,得到 %d", len(planned))
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// A@50/51ms(第一条,相对 base);B = A 末尾(52ms)+10ms = 62ms,@62/63ms。
	want := []time.Time{base.Add(50 * time.Millisecond), base.Add(51 * time.Millisecond), base.Add(62 * time.Millisecond), base.Add(63 * time.Millisecond)}
	if !equalTimes(times(planned), want) {
		t.Fatalf("链式 offset 时间=%v,期望 %v", times(planned), want)
	}
}

// TestPlanMessageOffsetNoCrossFlowHijack: 跨流独立——f1 的消息用 +100s 钉到自己,f2 无 offset
// 在 base 起步并发,不被 f1 拖到 100s 之后(问题 #1:跨流劫持在新模型下天然不成立)。
//
// f1(open=none/close=none, msg offset=+100s):data@100s、ack@100s+1ms。
// f2(无 offset):独立在 base 起步 data@0、ack@1ms。写盘序(按时间):f2 在前,f1 在后。
func TestPlanMessageOffsetNoCrossFlowHijack(t *testing.T) {
	mkMsg := func(offset *scenario.Offset) scenario.Message {
		return scenario.Message{
			From:       "src",
			OffsetTime: offset,
			Stack:      []scenario.Layer{ph("0xab")},
		}
	}
	s := &scenario.Scenario{
		BaseTime: mustAbs(t, "2024-01-01T00:00:00Z"),
		Flows: []scenario.FlowSpec{
			{Name: "f1", Stack: noneStack(), Messages: []scenario.Message{mkMsg(mustOffset(t, "+100s"))}},
			{Name: "f2", Stack: noneStack(), Messages: []scenario.Message{mkMsg(nil)}},
		},
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(planned) != 4 { // f1: data+ack=2, f2: data+ack=2
		t.Fatalf("期望 4 个包,得到 %d", len(planned))
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	// f2 在 base 并发起步:data@0、ack@1ms;f1 的 +100s 插队包在 100s。
	want := []time.Time{
		base, base.Add(time.Millisecond),
		base.Add(100 * time.Second), base.Add(100*time.Second + time.Millisecond),
	}
	if !equalTimes(times(planned), want) {
		t.Fatalf("跨流独立时间=%v,期望 %v", times(planned), want)
	}
	// 关键断言:f2 的首包(base)早于 f1 的插队包(base+100s)——f2 不被 f1 的 +100s 拖走。
	if !planned[0].Time.Before(planned[2].Time) {
		t.Errorf("f2 首包(%v) 应早于 f1 插队包(%v),说明 f2 被 f1 的插队消息跨流劫持了", planned[0].Time, planned[2].Time)
	}
}
