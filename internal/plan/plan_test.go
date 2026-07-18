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
	base := plan.DefaultBaseTime
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
	base := plan.DefaultBaseTime
	want := []time.Time{base, base.Add(time.Millisecond)}
	if !equalTimes(times(planned), want) {
		t.Fatalf("flow 默认时间=%v,期望 %v", times(planned), want)
	}
}

// TestPlanExplicitPacketOffset: 两个不同 offset 的 packet 能分别落到 base+offset 的位置。
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
	// 声明序 late(+10s)、early(+5ms);排序后 early(+5ms) 在前。
	want := []time.Time{origin.Add(5 * time.Millisecond), origin.Add(10 * time.Second)}
	if !equalTimes(times(planned), want) {
		t.Fatalf("显式时间=%v,期望 %v", times(planned), want)
	}
	if planned[0].Name != "early" || planned[1].Name != "late" {
		t.Fatalf("排序后 name 顺序=%v,期望 [early late]", names(planned))
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

// TestPlanMergeAndSort: packets + flow 显式时间交织,按 Time 排序后顺序与声明序不同。
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

// TestPlanStableSortForEqualTimes: 同 Time 的包保持声明/合并顺序(确定性)。
func TestPlanStableSortForEqualTimes(t *testing.T) {
	s := &scenario.Scenario{
		Packets: []scenario.Packet{
			udpPacket("first", mustOffset(t, "+5ms")),
			udpPacket("second", mustOffset(t, "+5ms")),
			udpPacket("third", mustOffset(t, "+5ms")),
		},
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	got := names(planned)
	want := []string{"first", "second", "third"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("同 Time 顺序=%v,期望 %v(稳定性被破坏)", got, want)
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

func names(planned []scenario.PlannedPacket) []string {
	out := make([]string, len(planned))
	for i, pp := range planned {
		out[i] = pp.Name
	}
	return out
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
