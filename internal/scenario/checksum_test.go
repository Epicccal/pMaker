package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 checksum 两态覆盖的 scenario 层校验:
//   - UDPFields.Checksum 字段可解析(UDP 此前连字段都没有)
//   - validateLayer 对 5 层(ipv4/tcp/udp/icmp/icmpv6)做 16 位值域校验,
//     超出 0xFFFF 报错(否则 Hex(uint32) 静默截断,等于没修)
//   - validateFlow 拒绝 flow.stack 上的 checksum 覆盖(展开器重建字段会丢弃),
//     且该拒绝优先于值域校验(对用户更有用的引导)

func hexPtr(v scenario.Hex) *scenario.Hex { return &v }

// TestValidateChecksumOver16BitsRejected 在 5 层各验证 checksum 超出 16 位时报错。
// 值 0x1FFFF 超过 0xFFFF;不加值域校验会被 Hex(uint32) 静默截断成 0xFFFF。
func TestValidateChecksumOver16BitsRejected(t *testing.T) {
	over := scenario.Hex(0x1FFFF)
	cases := []struct {
		name  string
		layer scenario.Layer
	}{
		{"ipv4", scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", Checksum: &over}}},
		{"tcp", scenario.Layer{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1, DPort: 80, Checksum: &over}}},
		{"udp", scenario.Layer{Type: "udp", Fields: &scenario.UDPFields{SPort: 1, DPort: 53, Checksum: &over}}},
		{"icmp", scenario.Layer{Type: "icmp", Fields: &scenario.ICMPFields{Checksum: &over}}},
		{"icmpv6", scenario.Layer{Type: "icmpv6", Fields: &scenario.ICMPv6Fields{Checksum: &over}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := scenario.Validate(&scenario.Scenario{Packets: []scenario.Packet{{Stack: []scenario.Layer{tc.layer}}}})
			if err == nil || !strings.Contains(err.Error(), "checksum 超出 16 位") {
				t.Fatalf("%s: Validate() error=%v,期望 checksum 超出 16 位", tc.name, err)
			}
		})
	}
}

// TestValidateChecksum16BitsAccepted 边界值 0xFFFF 应通过(只拦截越界,不拦截合法极值)。
func TestValidateChecksum16BitsAccepted(t *testing.T) {
	max := scenario.Hex(0xFFFF)
	s := &scenario.Scenario{Packets: []scenario.Packet{{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", Checksum: &max}},
			{Type: "udp", Fields: &scenario.UDPFields{SPort: 1, DPort: 53, Checksum: hexPtr(0)}},
		},
	}}}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("checksum=0xFFFF/0 应通过值域校验,实际失败: %v", err)
	}
}

// TestValidateFlowRejectsChecksumOverride: flow.stack 上写 checksum 静默无效
// (展开器 parseFlowStack 重建字段时丢弃 Checksum),validateFlow 应显式拒绝并引导
// standalone packet。flow.stack 只可能出现 eth/ipv4/ipv6/tcp/tcp_session(UDP 无 flow 支持),
// 此处覆盖 tcp 与 ipv4 两种代表情形。
func TestValidateFlowRejectsChecksumOverride(t *testing.T) {
	cases := []struct {
		name  string
		layer scenario.Layer
	}{
		{"tcp", scenario.Layer{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 80, Checksum: hexPtr(0xdead)}}},
		{"ipv4", scenario.Layer{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80", Checksum: hexPtr(0xdead)}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stack := []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
				tc.layer,
				{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "fin"}},
			}
			// tcp 用例:上面的 ipv4 已是网络层,tc.layer 是带 checksum 的 tcp,栈完整。
			// ipv4 用例:tc.layer 替换网络层,需移除上面那条裸 ipv4 避免双网络层。
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
			if err == nil || !strings.Contains(err.Error(), "暂不支持 checksum 覆盖") {
				t.Fatalf("%s: Validate() error=%v,期望拒绝 flow checksum 覆盖", tc.name, err)
			}
			if !strings.Contains(err.Error(), "standalone packet") {
				t.Fatalf("%s: 错误应引导改用 standalone packet,得到 %v", tc.name, err)
			}
		})
	}
}

// TestValidateFlowChecksumOverridePrioritizesUnsupported: flow.stack.tcp.checksum: 0x1FFFF
// 应报「不支持覆盖」而非「超出 16 位」—— 前者才是对用户更有用的引导。
func TestValidateFlowChecksumOverridePrioritizesUnsupported(t *testing.T) {
	over := scenario.Hex(0x1FFFF)
	flow := scenario.FlowSpec{
		Name: "f",
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 80, Checksum: &over}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "fin"}},
		},
		Messages: []scenario.Message{{From: "src", Stack: []scenario.Layer{
			{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}},
		}}},
	}
	err := scenario.Validate(&scenario.Scenario{Flows: []scenario.FlowSpec{flow}})
	if err == nil {
		t.Fatal("flow.stack.tcp.checksum 越界应报错")
	}
	if strings.Contains(err.Error(), "超出 16 位") {
		t.Fatalf("应优先报「不支持覆盖」而非值域错误,得到 %v", err)
	}
	if !strings.Contains(err.Error(), "暂不支持 checksum 覆盖") {
		t.Fatalf("期望「暂不支持 checksum 覆盖」,得到 %v", err)
	}
}
