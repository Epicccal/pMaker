package scenario_test

import (
	"slices"
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

// plainUDPFlowStack 是无 vxlan 的最小合法 UDP 会话 flow.stack(单段)。
func plainUDPFlowStack() []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "udp", Fields: &scenario.UDPFields{SPort: 5300, DPort: 53}},
		{Type: "udp_session", Fields: &scenario.UDPSessionFields{}},
	}
}

// TestFlowStackUDPSessionMatrix:udp_session 的分段校验矩阵 —— 互斥、传输层匹配、
// 必写(专门文案)、outer 段拒绝、合法形态。
func TestFlowStackUDPSessionMatrix(t *testing.T) {
	t.Run("合法:单段 UDP 会话", func(t *testing.T) {
		if err := validateFlowStack(t, plainUDPFlowStack()); err != nil {
			t.Fatalf("合法 UDP 会话栈报错: %v", err)
		}
	})
	t.Run("合法:VXLAN inner UDP 会话", func(t *testing.T) {
		s := vxlanFlowStackValid()
		s[6] = scenario.Layer{Type: "udp", Fields: &scenario.UDPFields{SPort: 5300, DPort: 53}}
		s[7] = scenario.Layer{Type: "udp_session", Fields: &scenario.UDPSessionFields{}}
		if err := validateFlowStack(t, s); err != nil {
			t.Fatalf("合法 inner UDP 会话栈报错: %v", err)
		}
	})
	t.Run("tcp_session 与 udp_session 并存被拒", func(t *testing.T) {
		s := plainUDPFlowStack()
		s = append(s[:3], append([]scenario.Layer{
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{}},
		}, s[3:]...)...)
		err := validateFlowStack(t, s)
		if err == nil || !strings.Contains(err.Error(), "会话层(tcp_session 或 udp_session)不可同时出现") {
			t.Fatalf("双会话层应报互斥错,error=%v", err)
		}
	})
	t.Run("udp_session 配 tcp 被拒(不匹配)", func(t *testing.T) {
		s := plainUDPFlowStack()
		s[2] = scenario.Layer{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 80}}
		err := validateFlowStack(t, s)
		if err == nil || !strings.Contains(err.Error(), "udp_session 需配 udp,当前为 tcp") {
			t.Fatalf("udp_session+tcp 应报不匹配错,error=%v", err)
		}
	})
	t.Run("tcp_session 配 udp 被拒(不匹配)", func(t *testing.T) {
		s := plainFlowStack()
		s[2] = scenario.Layer{Type: "udp", Fields: &scenario.UDPFields{SPort: 5300, DPort: 53}}
		err := validateFlowStack(t, s)
		if err == nil || !strings.Contains(err.Error(), "tcp_session 需配 tcp,当前为 udp") {
			t.Fatalf("tcp_session+udp 应报不匹配错,error=%v", err)
		}
	})
	t.Run("含 udp 无 tcp 无会话层给专门文案", func(t *testing.T) {
		s := plainUDPFlowStack()[:3] // eth/ipv4/udp
		err := validateFlowStack(t, s)
		if err == nil || !strings.Contains(err.Error(), "含 udp 无 tcp:UDP 会话需显式声明 udp_session") {
			t.Fatalf("udp 无会话层应给专门文案,error=%v", err)
		}
		// 不能落到误导性的「需要 tcp 层」。
		if strings.Contains(err.Error(), "需要 tcp 层") {
			t.Fatalf("udp 无会话层不应报「需要 tcp 层」(误导): %v", err)
		}
	})
	t.Run("udp_session 在 VXLAN outer 段被拒", func(t *testing.T) {
		vx := vxlanFlowStackValid()
		// outer 段尾部插入 udp_session;inner 段换成合法 UDP 会话。
		// 显式逐层构造,避免 append(s[:3], …) 复用底层数组把 vxlan 位置覆盖掉。
		stack := []scenario.Layer{
			vx[0], vx[1], vx[2], // outer eth/ipv4/udp
			{Type: "udp_session", Fields: &scenario.UDPSessionFields{}},
			vx[3],        // vxlan
			vx[4], vx[5], // inner eth/ipv4
			{Type: "udp", Fields: &scenario.UDPFields{SPort: 5300, DPort: 53}},
			{Type: "udp_session", Fields: &scenario.UDPSessionFields{}},
		}
		err := validateFlowStack(t, stack)
		if err == nil || !strings.Contains(err.Error(), "只能在 vxlan 之后的 inner 段") {
			t.Fatalf("outer 段 udp_session 应被拒,error=%v", err)
		}
	})
}

// TestFlowStackOuterSegmentBansTCP: outer 段带 tcp 被拒(need/ban 分派)。
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

// TestUDPStreamAppLayerWarning:UDP 会话的 message.stack 含 TCP 流式协议层时
// 照常出包、只产软告警(udp.stream-app-layer,按 tcpStreamLayers 正向判定);
// payload/payload_hex/dns 与 TCP 会话的流式层均不告警。
func TestUDPStreamAppLayerWarning(t *testing.T) {
	t.Run("流式层告警:code 与 path", func(t *testing.T) {
		f := scenario.FlowSpec{
			Name:  "u",
			Stack: plainUDPFlowStack(),
			Messages: []scenario.Message{{From: "src", Stack: []scenario.Layer{
				{Type: "http_request", Fields: &scenario.HTTPReqFields{Method: "GET", URL: "/a"}},
			}}},
		}
		ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{f}})
		if len(ws) != 1 {
			t.Fatalf("期望恰好一条告警,得到 %v", ws)
		}
		if ws[0].Code != scenario.CodeUDPStreamAppLayer {
			t.Errorf("code 应为 udp.stream-app-layer,得到 %q", ws[0].Code)
		}
		if ws[0].Path != "flows[0].messages[0].stack[0]" {
			t.Errorf("path 应为 flows[0].messages[0].stack[0],得到 %q", ws[0].Path)
		}
		if !strings.Contains(ws[0].Message, "http_request") || !strings.Contains(ws[0].Message, "可忽略") {
			t.Errorf("文案应点名层并提示可忽略,得到 %q", ws[0].Message)
		}
	})
	t.Run("数据报适用层不告警", func(t *testing.T) {
		for _, l := range []scenario.Layer{
			{Type: "payload", Fields: &scenario.PayloadFields{Payload: "q"}},
			{Type: "payload_hex", Fields: scenario.PayloadHex("0x00")},
			{Type: "dns", Fields: &scenario.DNSFields{ID: 0x1234}},
		} {
			f := scenario.FlowSpec{
				Name:     "u",
				Stack:    plainUDPFlowStack(),
				Messages: []scenario.Message{{From: "src", Stack: []scenario.Layer{l}}},
			}
			if ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{f}}); len(ws) != 0 {
				t.Errorf("层 %s 不应告警,得到 %v", l.Type, ws)
			}
		}
	})
	t.Run("流式层清单全量命中:表内层名皆真实且逐个告警", func(t *testing.T) {
		// 遍历真实表 tcpStreamLayers(经 TCPStreamLayersForTest 桥接,非测试内另抄副本),
		// 锁两个漂移方向:层名拼错/层被删(死条目)、表内层实际不告警(判定与表脱钩)。
		// Fields 留 nil:本检查只看 Type,其余 Check* 对 nil Fields 走 default 分支跳过,
		// 恰好把被测行为与别的告警隔离开。
		for _, name := range scenario.TCPStreamLayersForTest() {
			if !slices.Contains(scenario.LayerTypes(), name) {
				t.Errorf("%s 不是合法层名(tcpStreamLayers 与 layerDecoders 漂移)", name)
				continue
			}
			f := scenario.FlowSpec{
				Name:     "u",
				Stack:    plainUDPFlowStack(),
				Messages: []scenario.Message{{From: "src", Stack: []scenario.Layer{{Type: name}}}},
			}
			ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{f}})
			if len(ws) != 1 || ws[0].Code != scenario.CodeUDPStreamAppLayer {
				t.Errorf("流式层 %s 应恰好告警一次,得到 %v", name, ws)
			}
		}
	})
	t.Run("多层逐层告警", func(t *testing.T) {
		f := scenario.FlowSpec{
			Name:  "u",
			Stack: plainUDPFlowStack(),
			Messages: []scenario.Message{
				{From: "src", Stack: []scenario.Layer{
					{Type: "http_request", Fields: &scenario.HTTPReqFields{Method: "GET", URL: "/a"}},
					{Type: "payload", Fields: &scenario.PayloadFields{Payload: "tail"}},
				}},
				{From: "dst", Stack: []scenario.Layer{
					{Type: "http_response", Fields: &scenario.HTTPRespFields{Status: 200}},
				}},
			},
		}
		ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{f}})
		if len(ws) != 2 ||
			!strings.Contains(ws[0].Message, "messages[0].stack[0].http_request") ||
			!strings.Contains(ws[1].Message, "messages[1].stack[0].http_response") {
			t.Fatalf("期望两条流式层告警(其余层不告警),得到 %v", ws)
		}
	})
	t.Run("TCP 会话的流式层不告警", func(t *testing.T) {
		f := scenario.FlowSpec{
			Name:  "t",
			Stack: plainFlowStack(),
			Messages: []scenario.Message{{From: "src", Stack: []scenario.Layer{
				{Type: "http_request", Fields: &scenario.HTTPReqFields{Method: "GET", URL: "/a"}},
			}}},
		}
		if ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{f}}); len(ws) != 0 {
			t.Fatalf("TCP 会话的流式层是正常用法,不应告警,得到 %v", ws)
		}
	})
	t.Run("VXLAN 内层 UDP 会话同样覆盖", func(t *testing.T) {
		inner := plainUDPFlowStack()
		// vxlanFlowStackValid 前 4 层 = eth/ipv4/udp/vxlan,续接内层整栈(自带 eth)。
		s := slices.Concat(vxlanFlowStackValid()[:4], inner)
		f := scenario.FlowSpec{
			Name:  "vx",
			Stack: s,
			Messages: []scenario.Message{{From: "src", Stack: []scenario.Layer{
				{Type: "smtp_request", Fields: &scenario.SMTPRequestFields{Verb: "HELO", Args: "x"}},
			}}},
		}
		ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{f}})
		if len(ws) != 1 || !strings.Contains(ws[0].Message, "smtp_request") {
			t.Fatalf("隧道内层 UDP 会话的流式层应告警,得到 %v", ws)
		}
	})
}

// greFlowStack 是带一层 gre 的最小合法 flow.stack(两段,inner 无 eth)。
func greFlowStack() []scenario.Layer {
	return []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "1.1.1.1", Dst: "2.2.2.2"}},
		{Type: "gre", Fields: &scenario.GREFields{}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.10", Dst: "192.168.1.20"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 80}},
		{Type: "tcp_session", Fields: &scenario.TCPSessionFields{}},
	}
}

// TestFlowStackGRECut 切点规则表驱动:gre 与 vxlan 的两处规则差异
// (outer 传输层、inner eth)各取所需,GRE 两段栈放行、同形 VXLAN 仍拒、多切点拒。
func TestFlowStackGRECut(t *testing.T) {
	t.Run("GRE 两段栈(outer 无 udp、inner 无 eth)合法", func(t *testing.T) {
		if err := validateFlowStack(t, greFlowStack()); err != nil {
			t.Fatalf("GRE 隧道会话栈应通过,实际报错: %v", err)
		}
	})
	t.Run("GRE outer 直挂 IP,无传输层要求", func(t *testing.T) {
		// outer 段插 udp(GRE-in-UDP 形态)也放行:端口不承载隧道身份,不套 VXLAN 的
		// 「dport 须非零承载隧道身份」口径(sport/dport 的常规非零要求照常由单层校验生效)
		s := slices.Concat(greFlowStack()[:2], []scenario.Layer{
			{Type: "udp", Fields: &scenario.UDPFields{SPort: 51000, DPort: 4754}},
			{Type: "gre", Fields: &scenario.GREFields{}},
		}, greFlowStack()[3:])
		if err := validateFlowStack(t, s); err != nil {
			t.Fatalf("GRE-in-UDP 形态应通过,实际报错: %v", err)
		}
	})
	t.Run("GRE outer 段含 tcp 被拒(静默坏包防线)", func(t *testing.T) {
		// tcp 后跟 gre 会让外层 IPv4 protocol=6 却装 GRE 头;standalone 路径由
		// validateGREPosition 拦,flow 路径须在此对齐
		s := slices.Concat(greFlowStack()[:2], []scenario.Layer{
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 80}},
			{Type: "gre", Fields: &scenario.GREFields{}},
		}, greFlowStack()[3:])
		err := validateFlowStack(t, s)
		if err == nil || !strings.Contains(err.Error(), "外层段不允许 tcp") {
			t.Fatalf("GRE outer 段 tcp 应被拒,error=%v", err)
		}
	})
	t.Run("GRE inner 缺 eth 放行,同形 VXLAN 拒(切点规则差异)", func(t *testing.T) {
		// VXLAN 切点换成 gre 形状(去掉 outer udp、inner eth)须报「需要 eth 层」与「需要 udp 层」
		s := []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.20"}},
			{Type: "vxlan", Fields: &scenario.VXLANFields{VNI: 100}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.10", Dst: "192.168.1.20"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 80}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{}},
		}
		err := validateFlowStack(t, s)
		if err == nil || !strings.Contains(err.Error(), "stack.outer 需要 udp 层") {
			t.Fatalf("VXLAN outer 仍须 udp,error=%v", err)
		}
	})
	t.Run("GRE 多切点拒(报错点名 gre)", func(t *testing.T) {
		s := append(greFlowStack(), greFlowStack()[2])
		err := validateFlowStack(t, s)
		if err == nil || !strings.Contains(err.Error(), "暂只支持一层 gre 隧道") {
			t.Fatalf("双层 GRE 应报错,error=%v", err)
		}
	})
	t.Run("GRE 与 VXLAN 混合切点拒", func(t *testing.T) {
		s := slices.Concat(greFlowStack(), []scenario.Layer{
			{Type: "vxlan", Fields: &scenario.VXLANFields{VNI: 100}},
		})
		err := validateFlowStack(t, s)
		if err == nil || !strings.Contains(err.Error(), "暂只支持一层 vxlan 隧道") {
			t.Fatalf("GRE+VXLAN 叠加应报错,error=%v", err)
		}
	})
	t.Run("会话层在 GRE outer 段被拒(文案点名 gre)", func(t *testing.T) {
		s := greFlowStack()
		// tcp_session 插到 gre 之前(outer 段)
		stack := append(slices.Clone(s[:2]), append([]scenario.Layer{s[5]}, s[2:]...)...)
		err := validateFlowStack(t, stack)
		if err == nil || !strings.Contains(err.Error(), "只能在 gre 之后的 inner 段") {
			t.Fatalf("GRE outer 段 tcp_session 应被拒,error=%v", err)
		}
	})
	t.Run("GRE inner UDP 会话合法", func(t *testing.T) {
		s := greFlowStack()
		s[4] = scenario.Layer{Type: "udp", Fields: &scenario.UDPFields{SPort: 5300, DPort: 53}}
		s[5] = scenario.Layer{Type: "udp_session", Fields: &scenario.UDPSessionFields{}}
		if err := validateFlowStack(t, s); err != nil {
			t.Fatalf("GRE inner UDP 会话应通过,实际报错: %v", err)
		}
	})
}
