package scenario_test

import (
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 VLAN/eth 值域校验(vlan.go + validateLayer 的 vlan/eth 分支):
//   - vid 超 12 位(4096..65535)在 Validate 阶段报错,不再拖到 gopacket 序列化
//     (此前 vid: 5000 能通过 Parse+Validate,直到 build 阶段才被 gopacket 拒绝)
//   - vid 边界值 0(priority tag)与 4095(保留值)按字段表达能力放行
//   - pri(PCP)超 3 位(>7)在 Validate 阶段报错;边界 0/7 放行
//   - type / ethertype 超 16 位报错(Hex 底层 uint32,不拦截会被 builder 的
//     uint16 转换静默截断,与 checksum/length 同一失败模式)

func TestValidateVLANVIDOver12BitsRejected(t *testing.T) {
	cases := []struct {
		name string
		vid  uint16
	}{
		{"刚超界 4096", 4096},
		{"uint16 上限 65535", 65535},
		{"截断会变合法值 5000(0x1388→0x388=904)", 5000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scenario.Scenario{Packets: []scenario.Packet{{
				Stack: []scenario.Layer{
					{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
					{Type: "vlan", Fields: &scenario.VLANFields{VID: tc.vid}},
					{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				},
			}}}
			err := scenario.Validate(s)
			if err == nil || !strings.Contains(err.Error(), "vlan.vid 超出 12 位") {
				t.Fatalf("vid=%d: Validate() error=%v,期望 vlan.vid 超出 12 位", tc.vid, err)
			}
		})
	}
}

func TestValidateVLANVIDBoundaryAccepted(t *testing.T) {
	cases := []struct {
		name string
		vid  uint16
	}{
		{"0 = priority tag", 0},
		{"4095 = 12 位最大值(保留值按字段表达能力放行)", 4095},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scenario.Scenario{Packets: []scenario.Packet{{
				Stack: []scenario.Layer{
					{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
					{Type: "vlan", Fields: &scenario.VLANFields{VID: tc.vid}},
					{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				},
			}}}
			if err := scenario.Validate(s); err != nil {
				t.Fatalf("vid=%d 应通过值域校验,实际失败: %v", tc.vid, err)
			}
		})
	}
}

// TestValidateVLANPriOver3BitsRejected:pri(PCP)超 3 位须在 Validate 阶段报错。
// PCP 占 TCI 高 3 位,uint8 放得下 8-255,但落 wire 会与 DEI/VID 位混淆,故 scenario 层拦截。
func TestValidateVLANPriOver3BitsRejected(t *testing.T) {
	eight := uint8(8)
	s := &scenario.Scenario{Packets: []scenario.Packet{{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "vlan", Fields: &scenario.VLANFields{VID: 100, Pri: &eight}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		},
	}}}
	err := scenario.Validate(s)
	if err == nil || !strings.Contains(err.Error(), "vlan.pri 超出 3 位") {
		t.Fatalf("Validate() error=%v,期望 vlan.pri 超出 3 位", err)
	}
}

func TestValidateVLANPriBoundaryAccepted(t *testing.T) {
	seven := uint8(7)
	s := &scenario.Scenario{Packets: []scenario.Packet{{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "vlan", Fields: &scenario.VLANFields{VID: 100, Pri: &seven}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		},
	}}}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("pri=7 应通过值域校验,实际失败: %v", err)
	}
}

// TestValidateVLANHexOver16BitsRejected:type 超 16 位须在 Validate 阶段报错。
// 不拦截时 builder 的 uint16 转换会把 0x12345 静默截断成 0x2345,wire 值与配置不符。
func TestValidateVLANHexOver16BitsRejected(t *testing.T) {
	over := scenario.Hex(0x12345)
	cases := []struct {
		name   string
		fields *scenario.VLANFields
	}{
		{"type", &scenario.VLANFields{VID: 100, Type: &over}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scenario.Scenario{Packets: []scenario.Packet{{
				Stack: []scenario.Layer{
					{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
					{Type: "vlan", Fields: tc.fields},
					{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				},
			}}}
			err := scenario.Validate(s)
			want := "vlan." + tc.name + " 超出 16 位"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("Validate() error=%v,期望 %s", err, want)
			}
		})
	}
}

func TestValidateEthEtherTypeOver16BitsRejected(t *testing.T) {
	over := scenario.Hex(0x12345)
	s := &scenario.Scenario{Packets: []scenario.Packet{{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb", EtherType: &over}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		},
	}}}
	err := scenario.Validate(s)
	if err == nil || !strings.Contains(err.Error(), "eth.ethertype 超出 16 位") {
		t.Fatalf("Validate() error=%v,期望 eth.ethertype 超出 16 位", err)
	}
}

func TestValidateEthEtherType16BitsAccepted(t *testing.T) {
	max := scenario.Hex(0xFFFF)
	s := &scenario.Scenario{Packets: []scenario.Packet{{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb", EtherType: &max}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		},
	}}}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("ethertype=0xFFFF 应通过值域校验(断链构造是合法意图),实际失败: %v", err)
	}
}

// ---------- 方向化 VID(src_vid / dst_vid,仅 flow.stack 有效)----------
//
// 覆盖 vlan.go 的 validateVLANFields / validateVLANDirectionalVID:
//   - 与 vid 互斥(混写无唯一解释,拒绝静默取其一)
//   - 只在 flow.stack 内有效(standalone packets / message.stack 无方向语义)
//   - 两个方向字段各自复用 12 位值域校验,报错点名是哪个方向
//   - 单边缺省(该向摘层)与两边都写都合法

// dirFlow 造一条带方向化 VID 的最小 flow(vlan 夹在 eth 与 ipv4 之间)。
func dirFlow(v *scenario.VLANFields) scenario.FlowSpec {
	return scenario.FlowSpec{
		Name: "dir",
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "vlan", Fields: v},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1111, DPort: 80}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{}},
		},
		Messages: []scenario.Message{{
			From:  "src",
			Stack: []scenario.Layer{{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}}},
		}},
	}
}

func TestValidateVLANDirectionalVIDConflictsWithVID(t *testing.T) {
	u := func(v uint16) *uint16 { return &v }
	cases := []struct {
		name   string
		fields *scenario.VLANFields
	}{
		{"vid + src_vid", &scenario.VLANFields{VID: 100, SrcVID: u(300)}},
		{"vid + dst_vid", &scenario.VLANFields{VID: 100, DstVID: u(400)}},
		{"vid + 两向", &scenario.VLANFields{VID: 100, SrcVID: u(300), DstVID: u(400)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scenario.Scenario{Flows: []scenario.FlowSpec{dirFlow(tc.fields)}}
			err := scenario.Validate(s)
			if err == nil || !strings.Contains(err.Error(), "vlan.vid 与 vlan.src_vid/dst_vid 互斥") {
				t.Fatalf("Validate() error=%v,期望 vid 与方向 VID 互斥", err)
			}
		})
	}
}

// vid: 0 的零值与"未写"不可区分,故不构成冲突 —— 只写方向 VID 是最常见的写法。
func TestValidateVLANDirectionalVIDZeroVIDNotConflict(t *testing.T) {
	u := func(v uint16) *uint16 { return &v }
	cases := []struct {
		name   string
		fields *scenario.VLANFields
	}{
		{"只写 src_vid(下行摘层)", &scenario.VLANFields{SrcVID: u(300)}},
		{"只写 dst_vid(上行摘层)", &scenario.VLANFields{DstVID: u(400)}},
		{"两向都写", &scenario.VLANFields{SrcVID: u(300), DstVID: u(400)}},
		{"方向 VID 边界值 0/4095", &scenario.VLANFields{SrcVID: u(0), DstVID: u(4095)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scenario.Scenario{Flows: []scenario.FlowSpec{dirFlow(tc.fields)}}
			if err := scenario.Validate(s); err != nil {
				t.Fatalf("应通过校验,实际失败: %v", err)
			}
		})
	}
}

func TestValidateVLANDirectionalVIDOver12BitsRejected(t *testing.T) {
	u := func(v uint16) *uint16 { return &v }
	cases := []struct {
		name   string
		fields *scenario.VLANFields
		want   string
	}{
		{"src_vid 超界", &scenario.VLANFields{SrcVID: u(4096)}, "vlan.src_vid: vlan.vid 超出 12 位"},
		{"dst_vid 超界", &scenario.VLANFields{DstVID: u(5000)}, "vlan.dst_vid: vlan.vid 超出 12 位"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scenario.Scenario{Flows: []scenario.FlowSpec{dirFlow(tc.fields)}}
			err := scenario.Validate(s)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error=%v,期望 %s", err, tc.want)
			}
		})
	}
}

// TestValidateVLANDirectionalVIDOutsideFlowRejected:standalone packets 没有 src/dst
// 方向语义,写方向 VID 直接报错(不静默当 vid 用 —— 静默降级会生成与配置不符的包)。
func TestValidateVLANDirectionalVIDOutsideFlowRejected(t *testing.T) {
	u := func(v uint16) *uint16 { return &v }
	s := &scenario.Scenario{Packets: []scenario.Packet{{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "vlan", Fields: &scenario.VLANFields{SrcVID: u(300), DstVID: u(400)}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		},
	}}}
	err := scenario.Validate(s)
	if err == nil || !strings.Contains(err.Error(), "只在 flow.stack 内有效") {
		t.Fatalf("Validate() error=%v,期望拒绝 standalone packet 里的方向 VID", err)
	}
}

// TestValidateVLANDirectionalVIDFromYAML:走 Parse 全链路(字段名 src_vid/dst_vid
// 能被解码、不被未知字段校验拦下),与结构体直造路径互补。
func TestValidateVLANDirectionalVIDFromYAML(t *testing.T) {
	src := `
link_type: ethernet
flows:
  - name: dir
    stack:
      - eth:  { src: "00:11:22:33:44:55", dst: "66:77:88:99:aa:bb" }
      - vlan: { src_vid: 300, dst_vid: 400 }
      - ipv4: { src: "10.0.0.1", dst: "10.0.0.2" }
      - tcp:  { sport: 1111, dport: 80 }
      - tcp_session: { open: handshake, close: fin }
    messages:
      - from: src
        stack:
          - payload: { payload: "x" }
`
	s, err := scenario.Parse([]byte(src), t.TempDir())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	v, ok := s.Flows[0].Stack[1].Fields.(*scenario.VLANFields)
	if !ok {
		t.Fatalf("stack[1] 不是 vlan 层: %T", s.Flows[0].Stack[1].Fields)
	}
	if v.SrcVID == nil || *v.SrcVID != 300 || v.DstVID == nil || *v.DstVID != 400 {
		t.Fatalf("解码结果 src_vid=%v dst_vid=%v,期望 300/400", v.SrcVID, v.DstVID)
	}
}
