package flow_test

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/flow"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 UDP 会话(udp_session 标记层)的展开行为(flow/flow.go 的 TransportUDP 分支):
//   - 无握手 → 首包即第一条消息;无对端 ACK → 每消息恰 1 包;无挥手 → 末包即最后一条消息
//   - 相邻消息间隔 = offset_time(缺省 1ms);msgCursor 推进 = MessageDuration(UDP Profile)
//   - 方向反转只交换会话 UDP 层端口,eth/ip 照常反转
//   - ProfileOf 对 TCP(各 open/close 组合)与 UDP 的字段取值
// 端到端链路(Validate → plan → golden)见 internal/golden;校验矩阵见 internal/scenario。
// 单测直接构造 FlowSpec,不依赖 layerDecoders 是否登记 udp_session。

// udpFlowStack 是无 vxlan 的最小 UDP 会话栈。
func udpFlowStack() []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "udp", Fields: &scenario.UDPFields{SPort: 49152, DPort: 53}},
		{Type: "udp_session", Fields: &scenario.UDPSessionFields{}},
	}
}

// udpMsg 造一条 UDP 消息。
func udpMsg(from, body string) scenario.Message {
	return scenario.Message{
		From:  from,
		Stack: []scenario.Layer{{Type: "payload", Fields: &scenario.PayloadFields{Payload: body}}},
	}
}

// udpOf 取包里(唯一)UDP 层字段。
func udpOf(p scenario.Packet) *scenario.UDPFields {
	for _, l := range p.Stack {
		if u, ok := l.Fields.(*scenario.UDPFields); ok {
			return u
		}
	}
	return nil
}

// TestFlowUDPShape 无握手 / 无 ACK / 无挥手:两条消息恰展开 2 个包,
// 首包时刻 = anchor(第一条消息直接以流锚为参照),间隔缺省 1ms。
func TestFlowUDPShape(t *testing.T) {
	f := scenario.FlowSpec{
		Name:     "echo",
		Stack:    udpFlowStack(),
		Messages: []scenario.Message{udpMsg("src", "q"), udpMsg("dst", "a")},
	}
	anchor := time.Unix(0, 0).UTC()
	pkts, end, _, err := flow.Expand(f, anchor, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(pkts) != 2 {
		t.Fatalf("UDP 会话两条消息应恰 2 包(无握手/ACK/挥手),得到 %d", len(pkts))
	}
	// 首包即第一条消息:anchor + 0。
	if !pkts[0].Time.Equal(anchor) {
		t.Errorf("首包时刻=%v,期望 = anchor %v(UDP 无握手占位)", pkts[0].Time, anchor)
	}
	// 第二条消息缺省紧接上一条末尾(msgCursor + 0):首消息末尾 = 首包 + 1ms(TailSteps=1)。
	want2 := anchor.Add(1 * time.Millisecond)
	if !pkts[1].Time.Equal(want2) {
		t.Errorf("第二包时刻=%v,期望 %v(缺省 1ms 接续)", pkts[1].Time, want2)
	}
	// 流结束 = 末条消息 msgCursor = 第二包 + 1ms。
	wantEnd := anchor.Add(2 * time.Millisecond)
	if !end.Equal(wantEnd) {
		t.Errorf("流结束=%v,期望 %v(UDP 无挥手,msgCursor 即末尾)", end, wantEnd)
	}
}

// TestFlowUDPMessageOffsetTime 显式 offset_time 控制相邻消息间隔。
func TestFlowUDPMessageOffsetTime(t *testing.T) {
	off := mustUDPOffset(t, "+10ms")
	f := scenario.FlowSpec{
		Stack: udpFlowStack(),
		Messages: []scenario.Message{
			udpMsg("src", "q"),
			{From: "dst", OffsetTime: off, Stack: []scenario.Layer{
				{Type: "payload", Fields: &scenario.PayloadFields{Payload: "a"}},
			}},
		},
	}
	anchor := time.Unix(0, 0).UTC()
	pkts, _, _, err := flow.Expand(f, anchor, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(pkts) != 2 {
		t.Fatalf("期望 2 包,得到 %d", len(pkts))
	}
	want := anchor.Add(11 * time.Millisecond) // 首消息末尾(1ms)+ offset 10ms
	if !pkts[1].Time.Equal(want) {
		t.Errorf("第二包时刻=%v,期望 %v(上一条末尾 + offset_time)", pkts[1].Time, want)
	}
}

// TestFlowUDPDirectionReversal 方向反转:会话 UDP 层端口随方向交换;eth/ip 照常反转;
// payload 按消息落字节。
func TestFlowUDPDirectionReversal(t *testing.T) {
	f := scenario.FlowSpec{
		Stack:    udpFlowStack(),
		Messages: []scenario.Message{udpMsg("src", "q"), udpMsg("dst", "a")},
	}
	pkts, _, _, err := flow.Expand(f, time.Time{}, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	up, down := pkts[0].Packet, pkts[1].Packet

	u := udpOf(up)
	if u.SPort != 49152 || u.DPort != 53 {
		t.Errorf("上行包 UDP 端口=%d->%d,期望 49152->53(声明值)", u.SPort, u.DPort)
	}
	d := udpOf(down)
	if d.SPort != 53 || d.DPort != 49152 {
		t.Errorf("下行包 UDP 端口=%d->%d,期望 53->49152(会话层端口交换)", d.SPort, d.DPort)
	}
	// eth / ipv4 方向反转与 TCP 会话同一规则。
	ue := layerAt(up, "eth", 0).(*scenario.EthFields)
	de := layerAt(down, "eth", 0).(*scenario.EthFields)
	if de.Src != ue.Dst || de.Dst != ue.Src {
		t.Errorf("下行包 eth 未反转:%s->%s vs 上行 %s->%s", de.Src, de.Dst, ue.Src, ue.Dst)
	}
	ui := layerAt(up, "ipv4", 0).(*scenario.IPv4Fields)
	di := layerAt(down, "ipv4", 0).(*scenario.IPv4Fields)
	if di.Src != ui.Dst || di.Dst != ui.Src {
		t.Errorf("下行包 ipv4 未反转:%s->%s vs 上行 %s->%s", di.Src, di.Dst, ui.Src, ui.Dst)
	}
	// payload 各按消息。
	if got := payloadText(up); got != "q" {
		t.Errorf("上行包 payload=%q,期望 \"q\"", got)
	}
	if got := payloadText(down); got != "a" {
		t.Errorf("下行包 payload=%q,期望 \"a\"", got)
	}
}

// payloadText 解出包尾 payload_hex 的文本字节。
func payloadText(p scenario.Packet) string {
	for _, l := range p.Stack {
		if h, ok := l.Fields.(scenario.PayloadHex); ok {
			b, err := scenario.ParsePayloadHex(string(h))
			if err != nil {
				return ""
			}
			return string(b)
		}
	}
	return ""
}

// mustUDPOffset 经 YAML 解析路径把时长字符串解析为 Offset,失败即 Fatal。
func mustUDPOffset(t *testing.T, s string) *scenario.Offset {
	t.Helper()
	o := &scenario.Offset{}
	if err := yaml.Unmarshal([]byte(s), o); err != nil {
		t.Fatalf("解析 offset %q: %v", s, err)
	}
	return o
}

// TestFlowUDPMessageIDTimes msgCursor = 末包 + 1ms(TailSteps=1),与 TCP(+2ms)不同;
// 与 flow.MessageDuration(UDP Profile)同源。
func TestFlowUDPMessageIDTimes(t *testing.T) {
	f := scenario.FlowSpec{
		Stack: udpFlowStack(),
		Messages: []scenario.Message{
			{From: "src", MessageID: "m1", Stack: []scenario.Layer{
				{Type: "payload", Fields: &scenario.PayloadFields{Payload: "q1"}},
			}},
			{From: "dst", MessageID: "m2", Stack: []scenario.Layer{
				{Type: "payload", Fields: &scenario.PayloadFields{Payload: "a1"}},
			}},
		},
	}
	zero := time.Time{}
	_, _, msgids, err := flow.Expand(f, zero, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	// m1 数据@0,msgCursor=1ms;m2 数据@1ms,msgCursor=2ms。
	want := map[string]time.Time{
		"m1": zero.Add(1 * time.Millisecond),
		"m2": zero.Add(2 * time.Millisecond),
	}
	for k, w := range want {
		if got, ok := msgids[k]; !ok || !got.Equal(w) {
			t.Errorf("message_id %q 时刻=%v,期望 %v", k, got, w)
		}
	}
	// 算时与发包同源:MessageDuration(UDP) = TailSteps*DefaultStep = 1ms。
	p := flow.ProfileOf(f.Stack)
	dur, err := flow.MessageDuration(f.Messages[0], p)
	if err != nil {
		t.Fatalf("MessageDuration: %v", err)
	}
	if dur != 1*time.Millisecond {
		t.Errorf("UDP MessageDuration=%v,期望 1ms", dur)
	}
}

// TestFlowUDPNoSegmentSplitting 校验守护:UDP 消息即便误配 segment(校验阶段会拦),
// 展开层也不切段 —— 每消息仍 1 个数据报,与「UDP 无流重组」的模型一致。
func TestFlowUDPNoSegmentSplitting(t *testing.T) {
	f := scenario.FlowSpec{
		Stack: udpFlowStack(),
		Messages: []scenario.Message{{
			From:    "src",
			Segment: &scenario.Segment{MSS: 2},
			Stack:   []scenario.Layer{{Type: "payload", Fields: &scenario.PayloadFields{Payload: "abcdef"}}},
		}},
	}
	pkts, _, _, err := flow.Expand(f, time.Time{}, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if len(pkts) != 1 {
		t.Fatalf("UDP 消息不应切段,期望 1 包,得到 %d", len(pkts))
	}
	if got := payloadText(pkts[0].Packet); got != "abcdef" {
		t.Errorf("payload=%q,期望整条 \"abcdef\"", got)
	}
}

// TestProfileOf 对 TCP(各 open/close 组合)与 UDP 的字段取值。
func TestProfileOf(t *testing.T) {
	tcpStack := func(open, close string) []scenario.Layer {
		return []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "a", Dst: "b"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1, DPort: 2}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: open, Close: close}},
		}
	}
	cases := []struct {
		name      string
		stack     []scenario.Layer
		transport flow.Transport
		handshake int
		close     int
		tail      int
	}{
		{"TCP 缺省", tcpStack("", ""), flow.TransportTCP, 3, 4, 2},
		{"TCP handshake/fin", tcpStack("handshake", "fin"), flow.TransportTCP, 3, 4, 2},
		{"TCP none/none", tcpStack("none", "none"), flow.TransportTCP, 0, 0, 2},
		{"TCP handshake/rst", tcpStack("handshake", "rst"), flow.TransportTCP, 3, 1, 2},
		{"TCP 无会话层(可省)", tcpStack("", "")[:3], flow.TransportTCP, 3, 4, 2},
		{"UDP", udpFlowStack(), flow.TransportUDP, 0, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := flow.ProfileOf(tc.stack)
			if p.Transport != tc.transport || p.HandshakeSteps != tc.handshake ||
				p.CloseSteps != tc.close || p.TailSteps != tc.tail {
				t.Fatalf("ProfileOf=%+v,期望 {Transport:%d Handshake:%d Close:%d Tail:%d}",
					p, tc.transport, tc.handshake, tc.close, tc.tail)
			}
		})
	}
}
