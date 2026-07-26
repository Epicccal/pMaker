package plan_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 message 粒度定时:message.offset_time(相对上一条消息末尾,第一条相对握手完成后)、
// segment.interval(只作用于数据段,对端 ACK 用默认步长),以及流内链式 / 跨流独立语义。

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
// A(+50ms) 第一条,相对握手完成后(base)→ @50/51ms,末尾 52ms;B(+10ms) 相对 A 末尾 → 52ms+10ms=62ms,
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
