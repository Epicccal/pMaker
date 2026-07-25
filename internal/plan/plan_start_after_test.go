package plan_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 flow 级与 message 级 start_after:依赖锚定、offset 叠加、前向引用、
// 链式依赖、循环防御(防御性 no-progress 报错),以及 message 级 start_after 的
// msg/flow 引用、同流自引拒绝。

// flowWithTrigger 构造一条 open=none 的流,其唯一消息带 message_id=trigger,
// 起始于 anchor(无 offset 时 = base)。展开为:数据段@anchor、ACK@anchor+1ms、
// msgCursor=anchor+2ms(open=none 无握手,见 flow.go)。sport 用于区分多流同 Time 包。
func flowWithTrigger(name string, sport uint16) scenario.FlowSpec {
	f := baseFlow(name, nil)
	f.Stack[2].Fields.(*scenario.TCPFields).SPort = sport
	f.Messages[0].MessageID = "trigger"
	return f
}

// flowStartAfter 构造一条 open=none 的流,start_after 引用某 flow 的 trigger 消息,
// 展开为:数据段@anchor、ACK@anchor+1ms(sport 区分)。
func flowStartAfter(name, ref string, sport uint16) scenario.FlowSpec {
	f := baseFlow(name, nil)
	f.Stack[2].Fields.(*scenario.TCPFields).SPort = sport
	f.StartAfter = ref
	return f
}

// TestPlanStartAfter:flow B 用 start_after 引用 flow A 的 trigger 消息,
// 则 B 的锚 = A 的 msgCursor(B 数据段紧接 A 整组完成)。
//
// A(open=none,base 起):数据段@base、ACK@base+1ms、msgCursor=base+2ms。
// B start_after "a.trigger":锚=base+2ms → 数据段@base+2ms、ACK@base+3ms。
// 排序后:[A-data@base, A-ack@+1ms, B-data@+2ms, B-ack@+3ms]。
func TestPlanStartAfter(t *testing.T) {
	s := &scenario.Scenario{
		Flows: []scenario.FlowSpec{
			flowWithTrigger("a", 1111),
			flowStartAfter("b", "a.trigger", 2222),
		},
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(planned) != 4 {
		t.Fatalf("期望 4 个包,得到 %d", len(planned))
	}
	base := plan.DefaultBaseTime()
	want := []time.Time{base, base.Add(time.Millisecond), base.Add(2 * time.Millisecond), base.Add(3 * time.Millisecond)}
	if !equalTimes(times(planned), want) {
		t.Fatalf("start_after 时间=%v,期望 %v", times(planned), want)
	}
	// B 的数据段(base+2ms)应在 A 整组完成后;且 B 用 sport=2222 区分。
	sp, _ := tcpPorts(planned[2])
	if sp != 2222 {
		t.Errorf("第 3 包应为 B( sport 2222),得到 sport %d", sp)
	}
}

// TestPlanStartAfterOffsetGap:start_after + offset_time 叠加:B 锚 = A.msgCursor + offset。
func TestPlanStartAfterOffsetGap(t *testing.T) {
	s := &scenario.Scenario{
		Flows: []scenario.FlowSpec{
			flowWithTrigger("a", 1111),
			flowStartAfter("b", "a.trigger", 2222),
		},
	}
	s.Flows[1].OffsetTime = mustOffset(t, "+5ms") // B 锚 = (base+2ms) + 5ms = base+7ms
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	base := plan.DefaultBaseTime()
	// A-data@base, A-ack@+1ms, B-data@+7ms, B-ack@+8ms
	want := []time.Time{base, base.Add(time.Millisecond), base.Add(7 * time.Millisecond), base.Add(8 * time.Millisecond)}
	if !equalTimes(times(planned), want) {
		t.Fatalf("start_after+offset 时间=%v,期望 %v", times(planned), want)
	}
}

// TestPlanStartAfterForwardRef:被引 flow 声明在引用方之后也应解析(拓扑序,非声明序)。
func TestPlanStartAfterForwardRef(t *testing.T) {
	s := &scenario.Scenario{
		Flows: []scenario.FlowSpec{
			flowStartAfter("b", "a.trigger", 2222), // 先声明,引用后面的 a
			flowWithTrigger("a", 1111),             // 后声明,被引
		},
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	base := plan.DefaultBaseTime()
	// 声明序为 b,a;但时间排序:A-data@base, A-ack@+1ms, B-data@+2ms, B-ack@+3ms
	want := []time.Time{base, base.Add(time.Millisecond), base.Add(2 * time.Millisecond), base.Add(3 * time.Millisecond)}
	if !equalTimes(times(planned), want) {
		t.Fatalf("前向引用时间=%v,期望 %v", times(planned), want)
	}
	// 排序后:数据段 sport = 客户端口(A=1111, B=2222);对端 ACK 反转后 sport=80。
	// 故仅校验数据段(idx 0,2)的 sport。
	for _, idx := range []int{0, 2} {
		want := uint16(1111)
		if idx == 2 {
			want = 2222
		}
		sp, _ := tcpPorts(planned[idx])
		if sp != want {
			t.Errorf("数据段 idx=%d sport=%d,期望 %d", idx, sp, want)
		}
	}
}

// TestPlanStartAfterChain:A→B→C 链式 start_after,时间单调:A 完成后 B 起、B 完成后 C 起。
func TestPlanStartAfterChain(t *testing.T) {
	mk := func(name, ref string, sport uint16) scenario.FlowSpec {
		f := baseFlow(name, nil)
		f.Stack[2].Fields.(*scenario.TCPFields).SPort = sport
		f.Messages[0].MessageID = "trigger"
		if ref != "" {
			f.StartAfter = ref
		}
		return f
	}
	s := &scenario.Scenario{Flows: []scenario.FlowSpec{
		mk("a", "", 1111),
		mk("b", "a.trigger", 2222),
		mk("c", "b.trigger", 3333),
	}}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	base := plan.DefaultBaseTime()
	// A: data@base, ack@+1, msgCursor@+2;B 锚=base+2 → data@+2, ack@+3, msgCursor@+4;
	// C 锚=base+4 → data@+4, ack@+5。注意 B-data@+2 与 A 的 msgCursor@+2 同 Time,
	// 但 A 的 ACK@+1 在前;B-data@+2、C-data@+4 等按 Time 排序。
	want := []time.Time{
		base, base.Add(1 * time.Millisecond),
		base.Add(2 * time.Millisecond), base.Add(3 * time.Millisecond),
		base.Add(4 * time.Millisecond), base.Add(5 * time.Millisecond),
	}
	if !equalTimes(times(planned), want) {
		t.Fatalf("链式 start_after 时间=%v,期望 %v", times(planned), want)
	}
}

// TestPlanStartAfterCycleDefense:直接对未校验的循环场景调 Plan,应触发 plan 的
// 防御性 no-progress 报错(不死循环)。正常路径下循环由 Validate 拦截(见 load_test)。
func TestPlanStartAfterCycleDefense(t *testing.T) {
	mk := func(name, ref string) scenario.FlowSpec {
		f := baseFlow(name, nil)
		f.Stack[2].Fields.(*scenario.TCPFields).SPort = 1111
		f.Messages[0].MessageID = "trigger"
		f.StartAfter = ref
		return f
	}
	s := &scenario.Scenario{Flows: []scenario.FlowSpec{
		mk("a", "b.trigger"),
		mk("b", "a.trigger"),
	}}
	_, err := plan.Plan(s)
	if err == nil {
		t.Fatal("期望 Plan 对循环 start_after 报错(防御),实际通过")
	}
	if !strings.Contains(err.Error(), "循环依赖") {
		t.Errorf("错误应提及循环依赖,得到: %v", err)
	}
}

// --- message 级 start_after 测试 ---

// msgFlowWithTrigger:open=none,两条 payload 消息,第二条带 message_id=trigger。
func msgFlowWithTrigger(name string, sport uint16) scenario.FlowSpec {
	f := baseFlow(name, nil)
	f.Stack[2].Fields.(*scenario.TCPFields).SPort = sport
	f.Messages = []scenario.Message{
		{From: "src", Stack: []scenario.Layer{ph("0xaa")}},
		{From: "src", MessageID: "trigger", Stack: []scenario.Layer{ph("0xbb")}},
	}
	return f
}

func TestPlanMessageStartAfterMsgRef(t *testing.T) {
	b := baseFlow("b", nil)
	b.Stack[2].Fields.(*scenario.TCPFields).SPort = 2222
	b.Messages = []scenario.Message{
		{From: "src", Stack: []scenario.Layer{ph("0xcc")}},
		{From: "src", StartAfter: "a.trigger", Stack: []scenario.Layer{ph("0xdd")}},
	}
	s := &scenario.Scenario{Flows: []scenario.FlowSpec{
		msgFlowWithTrigger("a", 1111),
		b,
	}}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	base := plan.DefaultBaseTime()
	got := times(planned)
	want := []time.Time{
		base, base.Add(time.Millisecond),
		base, base.Add(time.Millisecond),
		base.Add(2 * time.Millisecond), base.Add(3 * time.Millisecond),
		base.Add(4 * time.Millisecond), base.Add(5 * time.Millisecond),
	}
	if !equalTimeMultiset(got, want) {
		t.Fatalf("message start_after 时间=%v,期望 %v", got, want)
	}
}

func TestPlanMessageStartAfterFlowRef(t *testing.T) {
	a := scenario.FlowSpec{
		Name: "a",
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80, ClientISN: 100, ServerISN: 200}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "none", Close: "fin"}},
		},
		Messages: []scenario.Message{{From: "src", Stack: []scenario.Layer{ph("0xaa")}}},
	}
	b := baseFlow("b", nil)
	b.Stack[2].Fields.(*scenario.TCPFields).SPort = 2222
	b.Messages = []scenario.Message{
		{From: "src", StartAfter: "a", Stack: []scenario.Layer{ph("0xbb")}},
	}
	s := &scenario.Scenario{Flows: []scenario.FlowSpec{a, b}}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	base := plan.DefaultBaseTime()
	var bData time.Time
	for _, pp := range planned {
		sp, _ := tcpPorts(pp)
		if sp == 2222 {
			if bData.IsZero() || pp.Time.Before(bData) {
				bData = pp.Time
			}
		}
	}
	if !bData.Equal(base.Add(6 * time.Millisecond)) {
		t.Fatalf("B.msg0 data=%v,期望 base+6ms(A 整流结束)", bData)
	}
}

func TestPlanMessageStartAfterSameFlowRejected(t *testing.T) {
	s := &scenario.Scenario{Flows: []scenario.FlowSpec{
		msgFlowWithTrigger("a", 1111),
	}}
	s.Flows[0].Messages[1].StartAfter = "a.trigger"
	if err := scenario.Validate(s); err == nil {
		t.Fatal("期望 Validate 拒绝同流自引的 message start_after,实际通过")
	} else if !strings.Contains(err.Error(), "禁止引用本 flow") {
		t.Errorf("错误应提及禁止引用本 flow,得到: %v", err)
	}
}

func TestPlanMessageStartAfterForwardRef(t *testing.T) {
	b := baseFlow("b", nil)
	b.Stack[2].Fields.(*scenario.TCPFields).SPort = 2222
	b.Messages = []scenario.Message{
		{From: "src", Stack: []scenario.Layer{ph("0xcc")}},
		{From: "src", StartAfter: "a.trigger", Stack: []scenario.Layer{ph("0xdd")}},
	}
	s := &scenario.Scenario{Flows: []scenario.FlowSpec{
		b,
		msgFlowWithTrigger("a", 1111),
	}}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	base := plan.DefaultBaseTime()
	bPorts := tcpPortSet(t, planned, 2222) // sport=2222 的是 B 的数据段(msg0-data, msg1-data)
	if len(bPorts) != 2 {
		t.Fatalf("B 应有 2 个数据段,得到 %d (%v)", len(bPorts), bPorts)
	}
	// msg0-data@base, msg1-data@base+4(= A.trigger cursor)。
	if !bPorts[1].Equal(base.Add(4 * time.Millisecond)) {
		t.Fatalf("前向引用 B.msg1 data=%v,期望 base+4ms", bPorts[1])
	}
}
