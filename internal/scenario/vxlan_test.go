package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 VXLAN 的 scenario 层校验:
//   - 单层规则(vni 24 位值域)走 validateLayer 路径
//   - 跨层位置规则(前 udp、后 inner eth)走 validateVXLANPosition 路径
//   - flow 禁用规则走 validateFlow 早拦截路径
//   - 明确不校验的内容(非标端口无 warning、双 eth 放行)加防回归断言

func vxlanStack(extra ...scenario.Layer) []scenario.Layer {
	base := []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "udp", Fields: &scenario.UDPFields{SPort: 49152, DPort: 4789}},
		{Type: "vxlan", Fields: &scenario.VXLANFields{VNI: 100}},
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:03", Dst: "00:00:00:00:00:04"}},
	}
	return append(base, extra...)
}

func vxlanPkt(stack []scenario.Layer) *scenario.Scenario {
	return &scenario.Scenario{Packets: []scenario.Packet{{Stack: stack}}}
}

// TestVXLANValid 合法场景:规范栈 + VNI 边界值(0、0xFFFFFF)+ valid_id_flag 两态。
func TestVXLANValid(t *testing.T) {
	cases := []struct {
		name  string
		vni   uint32
		valid *bool
	}{
		{"vni 0", 0, nil},
		{"vni max", 0xFFFFFF, nil},
		{"valid_id_flag false", 100, func() *bool { b := false; return &b }()},
		{"valid_id_flag true", 100, func() *bool { b := true; return &b }()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			extra := []scenario.Layer{
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 80}},
			}
			stack := vxlanStack(extra...)
			for _, l := range stack {
				if f, ok := l.Fields.(*scenario.VXLANFields); ok {
					f.VNI = c.vni
					f.ValidIDFlag = c.valid
				}
			}
			if err := scenario.Validate(vxlanPkt(stack)); err != nil {
				t.Fatalf("合法场景应通过校验,实际失败: %v", err)
			}
			if ws := scenario.Warnings(vxlanPkt(stack)); len(ws) != 0 {
				t.Fatalf("合法场景不应有 warning,得到 %v", ws)
			}
		})
	}
}

// TestVXLANVNITooLarge:VNI 超出 24 位在单层校验路径拦截。
func TestVXLANVNITooLarge(t *testing.T) {
	stack := vxlanStack()
	stack[3].Fields.(*scenario.VXLANFields).VNI = 0x1000000
	err := scenario.Validate(vxlanPkt(stack))
	if err == nil || !strings.Contains(err.Error(), "vxlan.vni 超出 24 位: 16777216") {
		t.Fatalf("Validate() error=%v,期望 vxlan.vni 超出 24 位", err)
	}
}

// TestVXLANPositionErrors:跨层位置规则 —— 前层非 udp、后层缺 inner eth。
func TestVXLANPositionErrors(t *testing.T) {
	t.Run("前一层是 ipv4 非 udp", func(t *testing.T) {
		stack := vxlanStack()
		stack[2] = scenario.Layer{Type: "gre", Fields: &scenario.GREFields{}}
		err := scenario.Validate(vxlanPkt(stack))
		if err == nil || !strings.Contains(err.Error(), "vxlan 前一层必须是 udp") {
			t.Fatalf("Validate() error=%v,期望 前一层必须是 udp", err)
		}
	})
	t.Run("vxlan 是首层", func(t *testing.T) {
		stack := vxlanStack()[3:]
		err := scenario.Validate(vxlanPkt(stack))
		if err == nil || !strings.Contains(err.Error(), "vxlan 前一层必须是 udp") {
			t.Fatalf("Validate() error=%v,期望 前一层必须是 udp", err)
		}
	})
	t.Run("缺 inner eth", func(t *testing.T) {
		stack := vxlanStack()[:4]
		err := scenario.Validate(vxlanPkt(stack))
		if err == nil || !strings.Contains(err.Error(), "vxlan 后必须紧跟 inner eth") {
			t.Fatalf("Validate() error=%v,期望 后必须紧跟 inner eth", err)
		}
	})
	t.Run("后层是 vlan 非 eth", func(t *testing.T) {
		stack := vxlanStack()
		stack[4] = scenario.Layer{Type: "vlan", Fields: &scenario.VLANFields{VID: 10}}
		err := scenario.Validate(vxlanPkt(stack))
		if err == nil || !strings.Contains(err.Error(), "vxlan 后必须紧跟 inner eth") {
			t.Fatalf("Validate() error=%v,期望 后必须紧跟 inner eth", err)
		}
	})
}

// TestVXLANDoubleEthAllowed:vxlan→eth→eth 不校验 inner eth 之后的内容(3.3 规则 4),
// 可构造的畸形用例照常生成;加断言防回归误加限制。
func TestVXLANDoubleEthAllowed(t *testing.T) {
	extra := []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:05", Dst: "00:00:00:00:00:06"}},
	}
	stack := vxlanStack(extra...)
	if err := scenario.Validate(vxlanPkt(stack)); err != nil {
		t.Fatalf("vxlan→eth→eth 应通过校验(不查 inner eth 之后),实际失败: %v", err)
	}
}

// TestVXLANNonStdPortNoWarning:非 4789 目的端口照常通过且无 warning(3.5 决策),
// 加断言防回归误加告警。
func TestVXLANNonStdPortNoWarning(t *testing.T) {
	extra := []scenario.Layer{
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 80}},
	}
	stack := vxlanStack(extra...)
	stack[2].Fields.(*scenario.UDPFields).DPort = 8472
	s := vxlanPkt(stack)
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("非标端口应通过校验,实际失败: %v", err)
	}
	if ws := scenario.Warnings(s); len(ws) != 0 {
		t.Fatalf("非标端口不应有 warning,得到 %v", ws)
	}
}

// TestVXLANRejectedInFlow:flow.stack 出现 vxlan 即报错,且先于值域校验(早拦截)。
func TestVXLANRejectedInFlow(t *testing.T) {
	flowStack := []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.80"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 80}},
		{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "fin"}},
		{Type: "vxlan", Fields: &scenario.VXLANFields{VNI: 0xFFFFFFFF}}, // 值域也非法,但 flow 禁用先报
	}
	s := &scenario.Scenario{Flows: []scenario.FlowSpec{{
		Name: "f", Stack: flowStack,
		Messages: []scenario.Message{{From: "src", Stack: []scenario.Layer{{Type: "payload_hex", Fields: scenario.PayloadHex("0xab")}}}},
	}}}
	err := scenario.Validate(s)
	if err == nil || !strings.Contains(err.Error(), "vxlan 不支持在 flow.stack 中使用") {
		t.Fatalf("Validate() error=%v,期望 flow 禁用报错", err)
	}
	if !strings.Contains(err.Error(), "standalone packets") {
		t.Fatalf("错误应引导改用 standalone packets,error=%v", err)
	}
}
