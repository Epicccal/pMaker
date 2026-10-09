package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 arp_consistency.go 的四条软告警:
// Gratuitous / Probe / Request 带非零目标 MAC / 长度字段不匹配。
// 一律经 scenario.Warnings 断言 —— 直接调 CheckARPWarnings 绕过聚合点会在
// Warnings() 漏接线时测试照绿,防线失效。硬错见 arp_validate_test.go。

// TestARPWarnings 逐 code 断言。
func TestARPWarnings(t *testing.T) {
	cases := []struct {
		name string
		f    *scenario.ARPLayer
		code string
		path string // 告警 Path 的后缀
	}{
		{"Gratuitous", &scenario.ARPLayer{
			Operation:       arpU16(2),
			SenderProtoAddr: "192.168.1.100",
			TargetProtoAddr: "192.168.1.100",
		}, "arp.gratuitous", ".sender_proto_addr"},
		{"Probe", &scenario.ARPLayer{
			Operation:       arpU16(1),
			SenderProtoAddr: "0.0.0.0",
			TargetProtoAddr: "192.168.1.1",
		}, "arp.probe", ".sender_proto_addr"},
		// 省略 sender_proto_addr 与显式 0.0.0.0 落线逐位相同,告警须一致(按文本判会漏)
		{"省略 sender_proto_addr 的 Probe", &scenario.ARPLayer{
			Operation:       arpU16(1),
			TargetProtoAddr: "192.168.1.1",
		}, "arp.probe", ".sender_proto_addr"},
		{"省略 sender_proto_addr 且 target 也全零", &scenario.ARPLayer{
			Operation:       arpU16(2),
			TargetProtoAddr: "0.0.0.0",
		}, "arp.gratuitous", ".sender_proto_addr"},
		{"Request 带非零目标 MAC", func() *scenario.ARPLayer {
			f := baseARP()
			f.TargetHWAddr = "00:0c:29:12:34:56"
			return f
		}(), "arp.request-non-zero-target-hw", ".target_hw_addr"},
		{"hardware_length 不匹配", func() *scenario.ARPLayer {
			f := baseARP()
			f.HardwareLength = arpU8(8)
			return f
		}(), "arp.length-mismatch", ".hardware_length"},
		{"protocol_length 不匹配", func() *scenario.ARPLayer {
			f := baseARP()
			f.ProtocolLength = arpU8(6)
			return f
		}(), "arp.length-mismatch", ".protocol_length"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ws := scenario.Warnings(arpPacket(c.f))
			found := false
			for _, w := range ws {
				if w.Code == c.code && strings.HasSuffix(w.Path, c.path) {
					found = true
				}
			}
			if !found {
				t.Fatalf("期望告警 %s(Path 后缀 %q),得到: %v", c.code, c.path, ws)
			}
		})
	}
}

// TestARPNoWarnings 规范场景不产告警:Reply 带零目标 MAC、覆盖值与地址长度一致、
// 长度字段显式写默认值(6/4)。
func TestARPNoWarnings(t *testing.T) {
	cases := []struct {
		name string
		f    *scenario.ARPLayer
	}{
		{"规范 Reply", &scenario.ARPLayer{
			Operation:       arpU16(2),
			SenderHWAddr:    "00:0c:29:aa:bb:cc",
			SenderProtoAddr: "192.168.1.1",
			TargetHWAddr:    "00:0c:29:12:34:56",
			TargetProtoAddr: "192.168.1.10",
		}},
		{"长度字段显式写默认值", func() *scenario.ARPLayer {
			f := baseARP()
			f.HardwareLength = arpU8(6)
			f.ProtocolLength = arpU8(4)
			return f
		}()},
		{"省略 sender_hw_addr(全零,Request 语义)", &scenario.ARPLayer{
			Operation:       arpU16(1),
			SenderProtoAddr: "192.168.1.1",
			TargetProtoAddr: "192.168.1.2",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if ws := scenario.Warnings(arpPacket(c.f)); len(ws) != 0 {
				t.Fatalf("不应有告警,得到: %v", ws)
			}
		})
	}
}
