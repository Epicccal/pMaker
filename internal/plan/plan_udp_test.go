package plan_test

import (
	"testing"
	"time"

	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 UDP flow(flow.stack 带 udp_session)参与跨流 start_after 的锚点对齐:
// 算时阶段(scheduler,经 ProfileOf)与发包阶段(flow.Expand)对 UDP 消息 msgCursor 的
// 认知必须一致 —— UDP 无握手/挥手/对端 ACK,msgCursor = 末包 + 1ms(TailSteps=1)。

// udpFlow 构造一条 UDP 会话流:每条消息展开恰 1 个数据报,无握手/ACK/挥手。
func udpFlow(name string, msgs ...scenario.Message) scenario.FlowSpec {
	return scenario.FlowSpec{
		Name: name,
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "udp", Fields: &scenario.UDPFields{SPort: 5300, DPort: 53}},
			{Type: "udp_session", Fields: &scenario.UDPSessionFields{}},
		},
		Messages: msgs,
	}
}

// TestPlanUDPStartAfterMsgRef:TCP 流 B 引用 UDP 流 A 的具名消息,B 锚 = A.msgCursor
// (= A 末包 + 1ms,无对端 ACK)。算时与发包同源的锚点对齐由此钉住。
//
// A(UDP,base 起):m0 数据@base,msgCursor=base+1ms。
// B(TCP open=none,start_after a.m0):数据@base+1ms、ACK@base+2ms。
func TestPlanUDPStartAfterMsgRef(t *testing.T) {
	a := udpFlow("a",
		scenario.Message{From: "src", MessageID: "m0", Stack: []scenario.Layer{ph("0xaa")}},
	)
	b := baseFlow("b", nil)
	b.Messages[0].StartAfter = "a.m0"
	s := &scenario.Scenario{Flows: []scenario.FlowSpec{a, b}}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	base := plan.DefaultBaseTime()
	got := times(planned)
	want := []time.Time{base, base.Add(time.Millisecond), base.Add(2 * time.Millisecond)}
	if !equalTimes(got, want) {
		t.Fatalf("UDP→TCP start_after 时间=%v,期望 %v(A 数据@base、B 数据@+1ms、B ACK@+2ms)", got, want)
	}
}

// TestPlanUDPStartAfterFlowRef:引用 UDP 流名时锚点 = 末条消息 msgCursor + CloseSteps(=0),
// 即末包 + 1ms。
//
// A(UDP,两条消息):m0@base、m1@base+1ms,msgCursor=base+2ms(流结束)。
// B(UDP,start_after "a"):m0 数据@base+2ms。
func TestPlanUDPStartAfterFlowRef(t *testing.T) {
	a := udpFlow("a",
		scenario.Message{From: "src", MessageID: "m0", Stack: []scenario.Layer{ph("0xaa")}},
		scenario.Message{From: "dst", MessageID: "m1", Stack: []scenario.Layer{ph("0xbb")}},
	)
	b := udpFlow("b",
		scenario.Message{From: "src", Stack: []scenario.Layer{ph("0xcc")}},
	)
	b.StartAfter = "a"
	s := &scenario.Scenario{Flows: []scenario.FlowSpec{a, b}}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	base := plan.DefaultBaseTime()
	got := times(planned)
	want := []time.Time{base, base.Add(time.Millisecond), base.Add(2 * time.Millisecond)}
	if !equalTimes(got, want) {
		t.Fatalf("UDP→UDP start_after 时间=%v,期望 %v(A 两包@base/+1ms、B 数据@+2ms)", got, want)
	}
}

// TestPlanUDPMessageIDCursorEqual:Expand 第三返回值(发包侧 msgCursor)与 plan 算时的
// mend(引用解析侧)给出同一时刻 —— 「算时与发包给出同一个答案」的不变式在 UDP 下的直接断言。
func TestPlanUDPMessageIDCursorEqual(t *testing.T) {
	off := mustOffset(t, "+3ms")
	a := udpFlow("a",
		scenario.Message{From: "src", MessageID: "m0", Stack: []scenario.Layer{ph("0xaa")}},
		scenario.Message{From: "src", OffsetTime: off, Stack: []scenario.Layer{ph("0xbb")}},
	)
	b := udpFlow("b",
		scenario.Message{From: "src", StartAfter: "a.m0", Stack: []scenario.Layer{ph("0xcc")}},
	)
	s := &scenario.Scenario{Flows: []scenario.FlowSpec{a, b}}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	base := plan.DefaultBaseTime()
	// A:m0@base、msgCursor=base+1ms;m1 起于 msgCursor+3ms=base+4ms(msgCursor=base+5ms,不发包)。
	// B 起于 a.m0 完成时刻 = base+1ms。实际包共 3 个:A.m0@base、B@+1ms、A.m1@+4ms。
	got := times(planned)
	want := []time.Time{base, base.Add(time.Millisecond), base.Add(4 * time.Millisecond)}
	if !equalTimes(got, want) {
		t.Fatalf("UDP msgCursor 时间=%v,期望 %v(A@base、B@+1ms、A.m1@+4ms)", got, want)
	}
	_ = planned
}
