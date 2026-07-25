package plan_test

import (
	"testing"
	"time"

	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖基本时序:默认时间策略、显式 packet/flow offset、packet↔flow 汇流排序、
// 同 Time 稳定排序与确定性。时间类型解析约束见 scenario 包 time_test.go。

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
