package plan_test

import (
	"encoding/hex"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件收录 plan 测试包共用的辅助函数与栈构造器,避免在各时间测试文件里复制。
// 协议/场景专属构造器随对应测试文件放置。

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

func equalTimeMultiset(a, b []time.Time) bool {
	if len(a) != len(b) {
		return false
	}
	ca := append([]time.Time(nil), a...)
	cb := append([]time.Time(nil), b...)
	sortTimes(ca)
	sortTimes(cb)
	for i := range ca {
		if !ca[i].Equal(cb[i]) {
			return false
		}
	}
	return true
}

func sortTimes(s []time.Time) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1].After(s[j]); j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func tcpPortSet(t *testing.T, planned []scenario.PlannedPacket, sport uint16) []time.Time {
	t.Helper()
	var out []time.Time
	for _, pp := range planned {
		sp, _ := tcpPorts(pp)
		if sp == sport {
			out = append(out, pp.Time)
		}
	}
	return out
}
