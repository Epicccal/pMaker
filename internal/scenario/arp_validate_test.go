package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 arp_validate.go 的硬错校验:
//   - validateARPFields 单层规则(operation 必填、target_proto_addr 必填与格式、
//     MAC/IPv4 字面格式)走 validateLayer 路径;
//   - flow.stack 不支持 arp 走 validateFlow 早拦截。
// 软告警见 arp_consistency_test.go。

// TestARPValidation 硬错路径:必填与格式错误一律经 scenario.Validate 报出,错误文案带字段路径。
func TestARPValidation(t *testing.T) {
	cases := []struct {
		name string
		f    *scenario.ARPLayer
		want string // Validate 返回的 error 子串
	}{
		{"缺 operation", func() *scenario.ARPLayer { f := baseARP(); f.Operation = nil; return f }(), "arp.operation"},
		{"缺 target_proto_addr", func() *scenario.ARPLayer { f := baseARP(); f.TargetProtoAddr = ""; return f }(), "arp.target_proto_addr"},
		{"target_proto_addr 非 IPv4", func() *scenario.ARPLayer { f := baseARP(); f.TargetProtoAddr = "2001:db8::1"; return f }(), "非法 IPv4"},
		{"sender_hw_addr 非法", func() *scenario.ARPLayer { f := baseARP(); f.SenderHWAddr = "zz:zz"; return f }(), "arp.sender_hw_addr"},
		{"target_hw_addr 非法", func() *scenario.ARPLayer { f := baseARP(); f.TargetHWAddr = "not-a-mac"; return f }(), "arp.target_hw_addr"},
		{"sender_proto_addr 非法", func() *scenario.ARPLayer { f := baseARP(); f.SenderProtoAddr = "10.0.0.300"; return f }(), "arp.sender_proto_addr"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := scenario.Validate(arpPacket(c.f))
			if err == nil {
				t.Fatalf("期望硬错含 %q,却通过校验", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("错误文案 %q 不含 %q", err.Error(), c.want)
			}
		})
	}
}

// TestARPValid 合法组合(含省略可选字段与 RARP operation),Validate 全通过。
func TestARPValid(t *testing.T) {
	cases := []struct {
		name string
		f    *scenario.ARPLayer
	}{
		{"最简 Request", baseARP()},
		{"省略 sender_hw_addr/proto_addr", &scenario.ARPLayer{Operation: arpU16(1), TargetProtoAddr: "192.168.1.1"}},
		{"Reply 带 target_hw_addr", &scenario.ARPLayer{
			Operation:       arpU16(2),
			SenderHWAddr:    "00:0c:29:aa:bb:cc",
			SenderProtoAddr: "192.168.1.1",
			TargetHWAddr:    "00:0c:29:12:34:56",
			TargetProtoAddr: "192.168.1.10",
		}},
		{"RARP Request", &scenario.ARPLayer{Operation: arpU16(3), SenderHWAddr: "00:11:22:33:44:55", TargetProtoAddr: "0.0.0.0"}},
		{"覆盖硬件/协议类型", &scenario.ARPLayer{
			Operation:       arpU16(1),
			HardwareType:    arpU16(6),
			ProtocolType:    arpU16(0x86dd),
			SenderProtoAddr: "192.168.1.1",
			TargetProtoAddr: "192.168.1.2",
		}},
		{"覆盖硬件/协议长度", &scenario.ARPLayer{
			Operation:       arpU16(1),
			HardwareLength:  arpU8(8),
			ProtocolLength:  arpU8(6),
			SenderProtoAddr: "192.168.1.1",
			TargetProtoAddr: "192.168.1.2",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := scenario.Validate(arpPacket(c.f)); err != nil {
				t.Fatalf("应通过校验,实际: %v", err)
			}
		})
	}
}

// TestARPFlowRejected:arp 是 wire 层不属于 flow 会话栈,flow.stack 里出现须早拒。
func TestARPFlowRejected(t *testing.T) {
	s := &scenario.Scenario{LinkType: "ethernet", Flows: []scenario.FlowSpec{{
		Name: "a",
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "arp", Fields: baseARP()},
		},
	}}}
	err := scenario.Validate(s)
	if err == nil {
		t.Fatal("flow.stack 含 arp 应报硬错")
	}
	if !strings.Contains(err.Error(), "arp") {
		t.Fatalf("错误文案 %q 未指出 arp", err.Error())
	}
}
