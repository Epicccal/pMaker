package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 GRE 的 scenario 层校验(gre.go):
//   - validateGREFields 单层规则(值域边界、checksum 三态互斥、C=0 offset 拦截)走 validateLayer 路径;
//   - validateGREPosition 跨层位置规则(前须 ipv4/ipv6);
//   - CheckGREWarnings 软告警(5 个 code)一律经 scenario.Warnings 断言 —— 直接调
//     CheckGRE* 绕过聚合点会在 Warnings() 漏接线时测试照绿,防线失效;
//   - flow 线的切点规则(gre 两段栈、gre inner 无 eth 放行、多切点拒)在 flow_stack_test.go。

// grePacket 构造含指定 GRE 字段的单包场景(标准承载:eth→ipv4→gre→ipv4→tcp)。
func grePacket(f *scenario.GREFields) *scenario.Scenario {
	return &scenario.Scenario{Packets: []scenario.Packet{{Stack: []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "1.1.1.1", Dst: "2.2.2.2"}},
		{Type: "gre", Fields: f},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"}},
		{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 80}},
	}}}}
}

func greU8(v uint8) *uint8 { return &v }
func greBool(v bool) *bool { return &v }

// hexPtr 复用 checksum_test.go 的同名 helper(签名一致,包内共享)。

// TestGREFieldsValid 合法场景:全部字段组合、边界值(key:0、flags:15、version:7)。
func TestGREFieldsValid(t *testing.T) {
	cases := []struct {
		name string
		f    *scenario.GREFields
	}{
		{"空层(4 字节头,向后兼容)", &scenario.GREFields{}},
		{"key 0 合法(K=1、Key=0,NVGRE FlowID 全零场景)", &scenario.GREFields{Key: hexPtr(0)}},
		{"key+seq", &scenario.GREFields{Key: hexPtr(0xa10b), Seq: new(uint32)}},
		{"checksum_present 自动算", &scenario.GREFields{ChecksumPresent: greBool(true)}},
		{"checksum 字面值", &scenario.GREFields{Checksum: hexPtr(0xdead)}},
		{"checksum_present+checksum 以值为准", &scenario.GREFields{ChecksumPresent: greBool(true), Checksum: hexPtr(0xdead)}},
		{"C=1 + offset 0 合法", &scenario.GREFields{ChecksumPresent: greBool(true), Offset: hexPtr(0)}},
		{"PPTP 组合", &scenario.GREFields{Protocol: hexPtr(0x880B), Version: greU8(1), Key: hexPtr(0x00080042), Seq: new(uint32), Ack: new(uint32)}},
		{"version 7 边界", &scenario.GREFields{Version: greU8(7)}},
		{"recursion 7 边界", &scenario.GREFields{Recursion: greU8(7)}},
		{"flags 15 边界(RFC 2637 Flags 全集上限)", &scenario.GREFields{Flags: greU8(15)}},
		{"protocol 0xFFFF 边界", &scenario.GREFields{Protocol: hexPtr(0xFFFF)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := scenario.Validate(grePacket(c.f)); err != nil {
				t.Fatalf("合法场景应通过校验,实际失败: %v", err)
			}
		})
	}
}

// TestGREFieldsRejected 硬错:值域越界(含决策 3 的 flags 15/16 回归锚)、
// checksum 三态矛盾、C=0 时 offset 非零被静默吞。packets 与 flow.stack 两入口同口径。
func TestGREFieldsRejected(t *testing.T) {
	cases := []struct {
		name string
		f    *scenario.GREFields
		want string
	}{
		{"version 8", &scenario.GREFields{Version: greU8(8)}, "version"},
		{"recursion 8", &scenario.GREFields{Recursion: greU8(8)}, "recursion"},
		// 决策 3 回归锚:15 过 16 拒,不是 7/8 —— 上限 15 恰是 RFC 2637 Flags(bits 9-12)全集
		{"flags 16 撞 A 位", &scenario.GREFields{Flags: greU8(16)}, "flags 超出值域 0-15"},
		{"protocol 0x10000", &scenario.GREFields{Protocol: hexPtr(0x10000)}, "protocol"},
		{"checksum 0x10000", &scenario.GREFields{Checksum: hexPtr(0x10000)}, "checksum"},
		{"offset 0x10000", &scenario.GREFields{Offset: hexPtr(0x10000)}, "offset"},
		{"checksum_present false + checksum", &scenario.GREFields{ChecksumPresent: func() *bool { b := false; return &b }(), Checksum: hexPtr(0xdead)}, "checksum_present"},
		{"C=0 + offset 非零被静默吞", &scenario.GREFields{Offset: hexPtr(0x1234)}, "offset"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := scenario.Validate(grePacket(c.f))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Validate() error=%v,期望报错含 %q", err, c.want)
			}
		})
	}
	// flow.stack 路径同口径:字段硬错经 validateFlowLayer → validateLayerIn 同样被拒
	// (接线靠约定不靠测试会静默失效,此处锁住 flow 校验循环不跳过 GRE 层)。
	t.Run("flow.stack 路径同拒", func(t *testing.T) {
		for _, c := range cases {
			f := scenario.FlowSpec{
				Name: "gre-bad",
				Stack: []scenario.Layer{
					{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
					{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "1.1.1.1", Dst: "2.2.2.2"}},
					{Type: "gre", Fields: c.f},
					{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"}},
					{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 80}},
					{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "none"}},
				},
				Messages: []scenario.Message{{From: "src", Stack: []scenario.Layer{
					{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}},
				}}},
			}
			err := scenario.Validate(&scenario.Scenario{Flows: []scenario.FlowSpec{f}})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("flow 路径 %s: error=%v,期望报错含 %q", c.name, err, c.want)
			}
		}
	})
}

// TestGREPositionRejected:gre 直挂 eth(首层 / 前层非 IP)报错。
func TestGREPositionRejected(t *testing.T) {
	t.Run("gre 是首层", func(t *testing.T) {
		s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: []scenario.Layer{
			{Type: "gre", Fields: &scenario.GREFields{}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"}},
		}}}}
		err := scenario.Validate(s)
		if err == nil || !strings.Contains(err.Error(), "gre 前一层必须是 ipv4/ipv6") {
			t.Fatalf("Validate() error=%v,期望 前一层必须是 ipv4/ipv6", err)
		}
	})
	t.Run("前一层是 eth", func(t *testing.T) {
		s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "gre", Fields: &scenario.GREFields{}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"}},
		}}}}
		err := scenario.Validate(s)
		if err == nil || !strings.Contains(err.Error(), "gre 前一层必须是 ipv4/ipv6") {
			t.Fatalf("Validate() error=%v,期望 前一层必须是 ipv4/ipv6", err)
		}
	})
}

// TestGREPositionTEBAllowed:gre→eth(TEB/NVGRE 形态)放行,不查 inner eth 之后;
// 与 VXLAN「不查 inner eth 之后」同口径。
func TestGREPositionTEBAllowed(t *testing.T) {
	s := &scenario.Scenario{Packets: []scenario.Packet{{Stack: []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "1.1.1.1", Dst: "2.2.2.2"}},
		{Type: "gre", Fields: &scenario.GREFields{Key: hexPtr(0x0012340a)}},
		{Type: "eth", Fields: &scenario.EthFields{Src: "aa:bb:cc:dd:ee:01", Dst: "aa:bb:cc:dd:ee:02"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"}},
		{Type: "udp", Fields: &scenario.UDPFields{SPort: 5000, DPort: 5001}},
	}}}}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("NVGRE 形态(内层 eth 自动推导 0x6558)应通过,实际失败: %v", err)
	}
}

// TestGREWarnings 软告警:逐 code 断言,统一经 scenario.Warnings(防漏接线,见文件头注释)。
func TestGREWarnings(t *testing.T) {
	cases := []struct {
		name string
		f    *scenario.GREFields
		code string
		path string // 告警 Path 的后缀(path+".recursion" 等)
	}{
		{"recursion 非零", &scenario.GREFields{Recursion: greU8(3)}, "gre.reserved-nonzero", ".recursion"},
		{"flags 非零", &scenario.GREFields{Flags: greU8(5)}, "gre.reserved-nonzero", ".flags"},
		{"C=1 + offset 非零", &scenario.GREFields{ChecksumPresent: greBool(true), Offset: hexPtr(0x1234)}, "gre.reserved-nonzero", ".offset"},
		{"version 未知", &scenario.GREFields{Version: greU8(2)}, "gre.version-unknown", ".version"},
		{"PPTP 缺 key", &scenario.GREFields{Version: greU8(1)}, "gre.pptp-missing-key", ""},
		{"version 0 写 ack", &scenario.GREFields{Ack: new(uint32)}, "gre.ack-outside-v1", ".ack"},
		{"显式 NVGRE 缺 key", &scenario.GREFields{Protocol: hexPtr(0x6558)}, "gre.nvgre-missing-key", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ws := scenario.Warnings(grePacket(c.f))
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

// TestGRENoWarnings 不触发告警的场景(PPTP 字段齐全、自动推导 TEB 不算 NVGRE)。
func TestGRENoWarnings(t *testing.T) {
	cases := []struct {
		name string
		f    *scenario.GREFields
	}{
		{"规范最简头", &scenario.GREFields{}},
		{"PPTP 字段齐全", &scenario.GREFields{Version: greU8(1), Key: hexPtr(0x00080042), Seq: new(uint32), Ack: new(uint32)}},
		// PPTP(v1) 下 Recur/Flags 语义由 RFC 2637 定义,不套 1701 保留位口径
		{"PPTP recursion 非零不告警", &scenario.GREFields{Version: greU8(1), Key: hexPtr(0x42), Recursion: greU8(2), Flags: greU8(3)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if ws := scenario.Warnings(grePacket(c.f)); len(ws) != 0 {
				t.Fatalf("不应有告警,得到: %v", ws)
			}
		})
	}
	t.Run("内层 eth 自动推导 0x6558 不触发 NVGRE 告警", func(t *testing.T) {
		// 只写 key 不写 protocol:TEB 由内层 eth 推导,非显式 NVGRE 声明,不该告警
		if ws := scenario.Warnings(grePacket(&scenario.GREFields{Key: hexPtr(0x42)})); len(ws) != 0 {
			t.Fatalf("TEB 桥接形态不应有告警,得到: %v", ws)
		}
	})
}

// TestGREFlowOverrideWarning:flow.stack 的 GRE 静态覆盖分流 —— checksum/seq/ack 告警
// (真值逐包变),key/protocol/version/recursion/flags 不告警(逐流恒定量)。
func TestGREFlowOverrideWarning(t *testing.T) {
	newFlow := func(f *scenario.GREFields) *scenario.Scenario {
		return &scenario.Scenario{Flows: []scenario.FlowSpec{{
			Name: "gre-flow",
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "1.1.1.1", Dst: "2.2.2.2"}},
				{Type: "gre", Fields: f},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 80}},
				{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "fin"}},
			},
			Messages: []scenario.Message{{From: "src", Stack: []scenario.Layer{{Type: "payload_hex", Fields: scenario.PayloadHex("0xab")}}}},
		}}}
	}
	t.Run("恒定字段不告警", func(t *testing.T) {
		s := newFlow(&scenario.GREFields{Protocol: hexPtr(0x0800), Key: hexPtr(0x42), Version: greU8(0), Recursion: greU8(0), Flags: greU8(0)})
		if ws := scenario.Warnings(s); len(ws) != 0 {
			t.Fatalf("恒定字段不应有告警,得到: %v", ws)
		}
	})
	t.Run("逐包变量字段告警", func(t *testing.T) {
		s := newFlow(&scenario.GREFields{Key: hexPtr(0x42), Checksum: hexPtr(0xdead), Seq: new(uint32), Ack: new(uint32)})
		ws := scenario.Warnings(s)
		for _, want := range []string{"checksum", "seq", "ack"} {
			found := false
			for _, w := range ws {
				if w.Code == "flow.override-static" && strings.HasSuffix(w.Path, "."+want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("期望 flow.override-static 告及 %s,得到: %v", want, ws)
			}
		}
	})
}

// TestGREWarningsFlowPath:CheckGREWarnings 的 flows 分支(flow.stack 里的 GRE 层
// 照常产出一致性告警,Path 落在 flows[i].stack[j] 上);与 packets 分支同 code 同语义。
func TestGREWarningsFlowPath(t *testing.T) {
	f := scenario.FlowSpec{
		Name: "gre-warn",
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "1.1.1.1", Dst: "2.2.2.2"}},
			{Type: "gre", Fields: &scenario.GREFields{Version: greU8(2)}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 80}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "handshake", Close: "fin"}},
		},
		Messages: []scenario.Message{{From: "src", Stack: []scenario.Layer{{Type: "payload_hex", Fields: scenario.PayloadHex("0xab")}}}},
	}
	ws := scenario.Warnings(&scenario.Scenario{Flows: []scenario.FlowSpec{f}})
	if len(ws) != 1 {
		t.Fatalf("期望恰好一条告警(version=2),得到: %v", ws)
	}
	if ws[0].Code != scenario.CodeGREVersionUnknown {
		t.Fatalf("code = %s,期望 %s", ws[0].Code, scenario.CodeGREVersionUnknown)
	}
	if !strings.HasPrefix(ws[0].Path, "flows[0]") || !strings.HasSuffix(ws[0].Path, ".version") {
		t.Fatalf("Path = %s,期望 flows[0] 前缀且 .version 后缀", ws[0].Path)
	}
	if !strings.Contains(ws[0].Message, "gre-warn") {
		t.Fatalf("Message 应点名 flow 名称 gre-warn,得到: %s", ws[0].Message)
	}
}
