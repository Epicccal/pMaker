package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 length 覆盖(两态语义)的 scenario 层校验,与 checksum_test.go 对称:
//   - 四层(ipv4/ipv6/tcp/udp)的长度字段可解析(此前 tcp/udp/ipv6 连字段都没有);
//   - 值域校验按字段宽度分别拦截:16 位字段(total_length/payload_length/udp length)
//     上限 0xFFFF,4 位字段(header_length/data_offset)上限 0xF ——
//     4 位字段用 16 位上限会放行 0xFF,在 (Version<<4)|IHL 里溢出污染 Version 半字节;
//   - validateFlow 拒绝 flow.stack 上的 length 覆盖(展开器重建字段会丢弃),
//     且该拒绝优先于值域校验(对用户更有用的引导)。

// TestValidateLengthRangeRejected 在各层验证长度字段越界时报错。
// 16 位字段写 0x1FFFF、4 位字段写 0x10(>0xF),应分别被拦截。
func TestValidateLengthRangeRejected(t *testing.T) {
	over16 := scenario.Hex(0x1FFFF)
	over4 := scenario.Hex(0x10)
	cases := []struct {
		name  string
		layer scenario.Layer
		want  string
	}{
		{"ipv4.total_length", scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", Length: &over16}}, "ipv4.total_length 超出 16 位"},
		{"ipv4.header_length", scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", IHL: &over4}}, "ipv4.header_length 超出 4 位"},
		{"ipv6.payload_length", scenario.Layer{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "::1", Dst: "::2", PayloadLength: &over16}}, "ipv6.payload_length 超出 16 位"},
		{"tcp.header_length", scenario.Layer{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1, DPort: 80, DataOffset: &over4}}, "tcp.header_length 超出 4 位"},
		{"udp.total_length", scenario.Layer{Type: "udp", Fields: &scenario.UDPFields{SPort: 1, DPort: 53, Length: &over16}}, "udp.total_length 超出 16 位"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := scenario.Validate(&scenario.Scenario{Packets: []scenario.Packet{{Stack: []scenario.Layer{tc.layer}}}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s: Validate() error=%v,期望含 %q", tc.name, err, tc.want)
			}
		})
	}
}

// TestValidateLengthBoundaryAccepted 边界值应通过:16 位字段 0xFFFF、4 位字段 0xF 与 0(显式 0)。
// 显式 0 是合法畸形(两态语义:写即覆盖、原样落 0),不得被值域校验拦截。
func TestValidateLengthBoundaryAccepted(t *testing.T) {
	max16 := scenario.Hex(0xFFFF)
	max4 := scenario.Hex(0xF)
	zero := scenario.Hex(0)
	s := &scenario.Scenario{Packets: []scenario.Packet{{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", Length: &max16, IHL: &max4}},
			{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "::1", Dst: "::2", PayloadLength: &zero}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1, DPort: 80, DataOffset: &zero}},
			{Type: "udp", Fields: &scenario.UDPFields{SPort: 1, DPort: 53, Length: &zero}},
		},
	}}}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("边界值应通过值域校验,实际失败: %v", err)
	}
}

// TestValidateFlowRejectsLengthOverride: flow.stack 上写长度覆盖静默无效
// (展开器 parseFlowStack 重建字段时丢弃这些长度指针),validateFlow 应显式拒绝并引导
// standalone packet。覆盖 tcp 与 ipv4 两种代表情形。
func TestValidateFlowRejectsLengthOverride(t *testing.T) {
	bad := scenario.Hex(0xFFFF)
	cases := []struct {
		name  string
		layer scenario.Layer
	}{
		{"tcp", scenario.Layer{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 80, DataOffset: &bad}}},
		{"ipv4", scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80", Length: &bad}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stack := []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
				tc.layer,
				{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "fin"}},
			}
			if tc.name == "ipv4" {
				stack = []scenario.Layer{
					{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
					tc.layer,
					{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 80}},
					{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "fin"}},
				}
			}
			flow := scenario.FlowSpec{
				Name:  "f",
				Stack: stack,
				Messages: []scenario.Message{{From: "src", Stack: []scenario.Layer{
					{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}},
				}}},
			}
			err := scenario.Validate(&scenario.Scenario{Flows: []scenario.FlowSpec{flow}})
			if err == nil || !strings.Contains(err.Error(), "暂不支持 length 覆盖") {
				t.Fatalf("%s: Validate() error=%v,期望拒绝 flow length 覆盖", tc.name, err)
			}
			if !strings.Contains(err.Error(), "standalone packet") {
				t.Fatalf("%s: 错误应引导改用 standalone packet,得到 %v", tc.name, err)
			}
		})
	}
}

// TestValidateFlowLengthOverridePrioritizesUnsupported: flow.stack.ipv4.total_length: 0x1FFFF
// 应报「不支持覆盖」而非「超出 16 位」—— 前者才是对用户更有用的引导。
func TestValidateFlowLengthOverridePrioritizesUnsupported(t *testing.T) {
	over := scenario.Hex(0x1FFFF)
	flow := scenario.FlowSpec{
		Name: "f",
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80", Length: &over}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 80}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "fin"}},
		},
		Messages: []scenario.Message{{From: "src", Stack: []scenario.Layer{
			{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}},
		}}},
	}
	err := scenario.Validate(&scenario.Scenario{Flows: []scenario.FlowSpec{flow}})
	if err == nil {
		t.Fatal("flow.stack.ipv4.total_length 越界应报错")
	}
	if strings.Contains(err.Error(), "超出 16 位") {
		t.Fatalf("应优先报「不支持覆盖」而非值域错误,得到 %v", err)
	}
	if !strings.Contains(err.Error(), "暂不支持 length 覆盖") {
		t.Fatalf("期望「暂不支持 length 覆盖」,得到 %v", err)
	}
}
