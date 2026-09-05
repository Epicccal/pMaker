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
//   - tpid / type / ethertype 超 16 位报错(Hex 底层 uint32,不拦截会被 builder 的
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

// TestValidateVLANHexOver16BitsRejected:tpid/type 超 16 位须在 Validate 阶段报错。
// 不拦截时 builder 的 uint16 转换会把 0x12345 静默截断成 0x2345,wire 值与配置不符。
func TestValidateVLANHexOver16BitsRejected(t *testing.T) {
	over := scenario.Hex(0x12345)
	cases := []struct {
		name   string
		fields *scenario.VLANFields
	}{
		{"tpid", &scenario.VLANFields{VID: 100, TPID: &over}},
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
