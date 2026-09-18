package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 flow.stack 分段校验(scenario/flow_stack.go):
// 层白名单、层序、同段重复/二选一、必备层、派生量拒写(seq/ack/flags)、
// outer udp.dport==0 硬错、多层 vxlan 拒绝;合法用例含两段隧道与版本异构。

// flowWith 构造单 flow 场景并跑 Validate,返回错误。
func validateFlowStack(t *testing.T, stack []scenario.Layer) error {
	t.Helper()
	f := scenario.FlowSpec{
		Stack: stack,
		Messages: []scenario.Message{{From: "src", Stack: []scenario.Layer{
			{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}},
		}}},
	}
	return scenario.Validate(&scenario.Scenario{Flows: []scenario.FlowSpec{f}})
}

// plainFlowStack 是无 vxlan 的最小合法 flow.stack(单段)。
func plainFlowStack() []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 80}},
		{Type: "tcp_session", Fields: &scenario.TCPSessionFields{}},
	}
}

// vxlanFlowStack 是带一层 vxlan 的最小合法 flow.stack(两段)。
func vxlanFlowStackValid() []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.20"}},
		{Type: "udp", Fields: &scenario.UDPFields{SPort: 51000, DPort: 4789}},
		{Type: "vxlan", Fields: &scenario.VXLANFields{VNI: 100}},
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:03", Dst: "00:00:00:00:00:04"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.10", Dst: "192.168.1.20"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 80}},
		{Type: "tcp_session", Fields: &scenario.TCPSessionFields{}},
	}
}

func TestValidateFlowSegmentRejects(t *testing.T) {
	seq := uint32(100)
	ack := uint32(200)
	cases := []struct {
		name  string
		stack []scenario.Layer
		want  string
	}{
		{
			name:  "乱序 tcp 在最前",
			stack: append([]scenario.Layer{plainFlowStack()[2]}, plainFlowStack()[:2]...),
			want:  "层序须为",
		},
		{
			name: "未知层 dns",
			stack: append(plainFlowStack()[:3], []scenario.Layer{
				{Type: "dns", Fields: &scenario.DNSFields{}},
			}...),
			want: "不支持该层",
		},
		{
			name: "单段双 eth",
			stack: func() []scenario.Layer {
				s := plainFlowStack()
				return append(s, s[0])
			}(),
			want: "层序须为",
		},
		{
			name: "同段 ipv4+ipv6",
			stack: append(plainFlowStack()[:2], []scenario.Layer{
				{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2"}},
				plainFlowStack()[2],
			}...),
			want: "不可同时出现",
		},
		{
			name: "tcp 写 seq",
			stack: func() []scenario.Layer {
				s := plainFlowStack()
				s[2].Fields.(*scenario.TCPFields).Seq = &seq
				return s
			}(),
			want: "由展开器按连接状态推导",
		},
		{
			name: "tcp 写 flags",
			stack: func() []scenario.Layer {
				s := plainFlowStack()
				s[2].Fields.(*scenario.TCPFields).Flags = []string{"SYN"}
				return s
			}(),
			want: "由展开器按连接状态推导",
		},
		{
			name: "tcp 写 ack",
			stack: func() []scenario.Layer {
				s := plainFlowStack()
				s[2].Fields.(*scenario.TCPFields).Ack = &ack
				return s
			}(),
			want: "由展开器按连接状态推导",
		},
		{
			name: "单段出现 udp(被禁)",
			stack: func() []scenario.Layer {
				s := plainFlowStack()
				return append(s[:2], append([]scenario.Layer{
					{Type: "udp", Fields: &scenario.UDPFields{SPort: 5, DPort: 6}},
				}, s[2])...)
			}(),
			want: "不可同时出现",
		},
		{
			name: "outer 段出现 tcp_session",
			stack: func() []scenario.Layer {
				s := vxlanFlowStackValid()
				// tcp_session 插入 vxlan 之前(outer 段),触发 segOuter && seen["tcp_session"]
				return append(s[:3], append([]scenario.Layer{s[7]}, s[3:]...)...)
			}(),
			want: "只能在 vxlan 之后的 inner 段",
		},
		{
			name:  "inner 段缺 eth",
			stack: vxlanFlowStackValid()[:4],
			want:  "需要 eth 层",
		},
		{
			name:  "多层 vxlan",
			stack: append(vxlanFlowStackValid(), vxlanFlowStackValid()[3]),
			want:  "暂只支持一层 vxlan 隧道",
		},
		{
			name: "outer udp dport=0",
			stack: func() []scenario.Layer {
				s := vxlanFlowStackValid()
				s[2].Fields.(*scenario.UDPFields).DPort = 0
				return s
			}(),
			want: "dport 须非零",
		},
		{
			name: "inner 段带 udp",
			stack: func() []scenario.Layer {
				s := vxlanFlowStackValid()
				// udp 插在 inner 段 tcp 之前(同 rank 3 异类),触发"不可同时出现"
				inner := []scenario.Layer{
					s[4], // eth
					s[5], // ipv4
					{Type: "udp", Fields: &scenario.UDPFields{SPort: 5, DPort: 6}},
					s[6], // tcp
					s[7], // tcp_session
				}
				return append(s[:4], inner...)
			}(),
			want: "不可同时出现",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateFlowStack(t, tc.stack)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error=%v,期望含 %q", err, tc.want)
			}
		})
	}
}

func TestValidateFlowSegmentAccepts(t *testing.T) {
	cases := []struct {
		name  string
		stack []scenario.Layer
	}{
		{name: "单段现状栈", stack: plainFlowStack()},
		{name: "两段 vxlan 隧道", stack: vxlanFlowStackValid()},
		{
			name: "ipv6 underlay + ipv4 overlay(版本异构)",
			stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
				{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::10", Dst: "2001:db8::20"}},
				{Type: "udp", Fields: &scenario.UDPFields{SPort: 51000, DPort: 4789}},
				{Type: "vxlan", Fields: &scenario.VXLANFields{VNI: 200}},
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:03", Dst: "00:00:00:00:00:04"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.10", Dst: "192.168.1.20"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 443}},
				{Type: "tcp_session", Fields: &scenario.TCPSessionFields{}},
			},
		},
		{
			name: "outer dport 非标 8472 合法",
			stack: func() []scenario.Layer {
				s := vxlanFlowStackValid()
				s[2].Fields.(*scenario.UDPFields).DPort = 8472
				return s
			}(),
		},
		{
			name: "QinQ 标签链",
			stack: func() []scenario.Layer {
				s := plainFlowStack()
				out := []scenario.Layer{s[0]}
				out = append(out,
					scenario.Layer{Type: "vlan", Fields: &scenario.VLANFields{VID: 100}},
					scenario.Layer{Type: "vlan", Fields: &scenario.VLANFields{VID: 200}})
				return append(out, s[1:]...)
			}(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateFlowStack(t, tc.stack); err != nil {
				t.Fatalf("%s: 合法栈报错: %v", tc.name, err)
			}
		})
	}
}

// TestFlowStackTCPMessageRequiredOuterDPortZeroTCP: outer 段带 tcp 被拒(need/ban 分派)。
func TestFlowStackOuterSegmentBansTCP(t *testing.T) {
	s := vxlanFlowStackValid()
	s[2] = scenario.Layer{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 80}}
	err := validateFlowStack(t, s)
	if err == nil || !strings.Contains(err.Error(), "stack.outer 需要 udp 层") {
		t.Fatalf("outer 段带 tcp 应被拒,error=%v", err)
	}
}

// TestFlowLengthOverrideWarning: flow.stack 上每个可覆盖的长度字段都产一条软告警
// (CheckFlowOverrideWarning);standalone packets 与不写覆盖时不告警。
func TestFlowLengthOverrideWarning(t *testing.T) {
	cases := []struct {
		name  string
		layer scenario.Layer
		want  string
	}{
		{"ipv4 total_length", scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", Length: hexPtr(0x9999)}}, "stack[1].total_length"},
		{"ipv4 header_length", scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", IHL: hexPtr(0x5)}}, "stack[1].header_length"},
		{"ipv6 payload_length", scenario.Layer{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2", PayloadLength: hexPtr(0x9999)}}, "stack[1].payload_length"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := plainFlowStack()
			s[1] = tc.layer
			ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{{Name: "f", Stack: s}}})
			if len(ws) != 1 || !strings.Contains(ws[0].Message, tc.want) {
				t.Fatalf("期望一条含 %q 的告警,得到 %v", tc.want, ws)
			}
		})
	}

	// tcp header_length 与 udp total_length:udp 只在 vxlan outer 段出现,一并覆盖。
	t.Run("tcp header_length 与 outer udp total_length", func(t *testing.T) {
		s := vxlanFlowStackValid()
		s[2].Fields.(*scenario.UDPFields).Length = hexPtr(0x9999)
		s[6].Fields.(*scenario.TCPFields).DataOffset = hexPtr(0x5)
		ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{{Name: "vx", Stack: s}}})
		if len(ws) != 2 ||
			!strings.Contains(ws[0].Message, "stack[2].total_length") ||
			!strings.Contains(ws[1].Message, "stack[6].header_length") {
			t.Fatalf("期望 udp/tcp 各一条告警,得到 %v", ws)
		}
	})

	t.Run("无覆盖不告警", func(t *testing.T) {
		if ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{{Name: "f", Stack: plainFlowStack()}}}); len(ws) != 0 {
			t.Fatalf("无 length 覆盖不应告警,得到 %v", ws)
		}
	})
}

// TestFlowChecksumOverrideWarning: checksum 覆盖真值逐包变(伪首部/seq/ack/方向/payload 全变),
// 应照 length 同告警;唯一豁免 = VXLAN 外层 UDP 在 IPv4 underlay 下写 0(RFC 7348 §5 免校验)。
func TestFlowChecksumOverrideWarning(t *testing.T) {
	t.Run("内层 tcp checksum 告警", func(t *testing.T) {
		s := plainFlowStack()
		s[2].Fields.(*scenario.TCPFields).Checksum = hexPtr(0x1234)
		ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{{Name: "f", Stack: s}}})
		if len(ws) != 1 || !strings.Contains(ws[0].Message, "stack[2].checksum") {
			t.Fatalf("期望一条含 stack[2].checksum 的告警,得到 %v", ws)
		}
	})
	t.Run("ipv4 头 checksum 告警", func(t *testing.T) {
		s := plainFlowStack()
		s[1].Fields.(*scenario.IPv4Fields).Checksum = hexPtr(0x1234)
		ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{{Name: "f", Stack: s}}})
		if len(ws) != 1 || !strings.Contains(ws[0].Message, "stack[1].checksum") {
			t.Fatalf("期望一条含 stack[1].checksum 的告警,得到 %v", ws)
		}
	})
	t.Run("内层 ipv4 头 checksum 告警", func(t *testing.T) {
		s := vxlanFlowStackValid()
		s[5].Fields.(*scenario.IPv4Fields).Checksum = hexPtr(0x1234)
		ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{{Name: "vx", Stack: s}}})
		if len(ws) != 1 || !strings.Contains(ws[0].Message, "stack[5].checksum") {
			t.Fatalf("期望一条含 stack[5].checksum 的告警,得到 %v", ws)
		}
	})
	t.Run("外层 udp 非零 checksum 告警", func(t *testing.T) {
		s := vxlanFlowStackValid()
		s[2].Fields.(*scenario.UDPFields).Checksum = hexPtr(0x1234)
		ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{{Name: "vx", Stack: s}}})
		if len(ws) != 1 || !strings.Contains(ws[0].Message, "stack[2].checksum") {
			t.Fatalf("期望一条含 stack[2].checksum 的告警,得到 %v", ws)
		}
	})
	t.Run("外层 udp checksum=0 over ipv4 豁免", func(t *testing.T) {
		s := vxlanFlowStackValid()
		s[2].Fields.(*scenario.UDPFields).Checksum = hexPtr(0)
		if ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{{Name: "vx", Stack: s}}}); len(ws) != 0 {
			t.Fatalf("IPv4 underlay 外层 UDP 零校验和应豁免,得到 %v", ws)
		}
	})
	t.Run("外层 udp checksum=0 over ipv6 告警", func(t *testing.T) {
		s := []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::10", Dst: "2001:db8::20"}},
			{Type: "udp", Fields: &scenario.UDPFields{SPort: 51000, DPort: 4789, Checksum: hexPtr(0)}},
			{Type: "vxlan", Fields: &scenario.VXLANFields{VNI: 200}},
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:03", Dst: "00:00:00:00:00:04"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.10", Dst: "192.168.1.20"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 443}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{}},
		}
		ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{{Name: "v6", Stack: s}}})
		if len(ws) != 1 || !strings.Contains(ws[0].Message, "stack[2].checksum") {
			t.Fatalf("IPv6 underlay 外层 UDP 零校验和应告警(强制校验),得到 %v", ws)
		}
	})
	t.Run("普通 ipv4 UDP checksum=0 豁免(就近判定,不限 VXLAN outer)", func(t *testing.T) {
		// 就近网络层为 IPv4 时 checksum 0 是 RFC 768 的合法恒定值,不适用
		// flow.override-static(其前提是"真值逐包变")。单段 UDP 栈(将来 udp_session)
		// 与 VXLAN outer 同判。
		s := []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "udp", Fields: &scenario.UDPFields{SPort: 51000, DPort: 53, Checksum: hexPtr(0)}},
		}
		if ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{{Name: "u", Stack: s}}}); len(ws) != 0 {
			t.Fatalf("普通 IPv4 UDP 零校验和应豁免,得到 %v", ws)
		}
	})
	t.Run("双 UDP 栈就近判定:outer 与 inner 各绑其前网络层", func(t *testing.T) {
		// IPv6 underlay + IPv4 overlay:outer UDP(前为 ipv6)checksum 0 告警;
		// inner UDP(前为 ipv4)checksum 0 豁免。旧判据取第一个网络层(ipv6),
		// 会把 inner 误判为告警 —— 本用例锁住逐层就近语义。
		s := []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "2001:db8::10", Dst: "2001:db8::20"}},
			{Type: "udp", Fields: &scenario.UDPFields{SPort: 51000, DPort: 4789, Checksum: hexPtr(0)}},
			{Type: "vxlan", Fields: &scenario.VXLANFields{VNI: 200}},
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:03", Dst: "00:00:00:00:00:04"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.10", Dst: "192.168.1.20"}},
			{Type: "udp", Fields: &scenario.UDPFields{SPort: 5300, DPort: 53, Checksum: hexPtr(0)}},
		}
		ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{{Name: "mix", Stack: s}}})
		if len(ws) != 1 || !strings.Contains(ws[0].Message, "stack[2].checksum") {
			t.Fatalf("期望仅 outer(ipv6 就近)一条告警,inner(ipv4 就近)应豁免,得到 %v", ws)
		}
	})
}
