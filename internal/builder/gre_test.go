package builder_test

import (
	"strings"
	"testing"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 GRE 的 builder 侧接线(ip.go 的 greProtoFor / buildGRE):
//   - greProtoFor 推导表(内层 eth → 0x6558 TEB)与 ethTypeFor 未被污染;
//   - GREFields 字段落 layers.GRE(写即置位,gopacket 回读读回 Key/Seq/Ack/Version);
//   - checksum 三态:checksum_present=true 自动算、checksum 字面值原样落不被改回;
//   - 空层(- gre: {})产 4 字节头,向后兼容。

// greScenario 构造 eth→ipv4→gre(指定字段)→tail 场景并出 pcap。
func greScenario(t *testing.T, f *scenario.GREFields, tailType string, tailFields any) []byte {
	return buildScenarioPcap(t, &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "1.1.1.1", Dst: "2.2.2.2"}},
			{Type: "gre", Fields: f},
			{Type: tailType, Fields: tailFields},
		},
	}}})
}

// 指针 helper 复用既有定义:hexPtr(ip_test.go)、u8ptr(helpers_test.go)、boolPtr(imap_test.go)。

// TestGREProtoDerivation GRE.Protocol 按内层推导:ipv4 → 0x0800、ipv6 → 0x86dd、
// eth → 0x6558(TEB,greProtoFor 补的那条)。
func TestGREProtoDerivation(t *testing.T) {
	cases := []struct {
		name   string
		tail   string
		fields any
		want   layers.EthernetType
	}{
		{"inner ipv4", "ipv4", &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"}, layers.EthernetTypeIPv4},
		{"inner ipv6", "ipv6", &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2"}, layers.EthernetTypeIPv6},
		{"inner eth(TEB)", "eth", &scenario.EthFields{Src: "aa:bb:cc:dd:ee:01", Dst: "aa:bb:cc:dd:ee:02"}, layers.EthernetTypeTransparentEthernetBridging},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkts := readPackets(t, greScenario(t, &scenario.GREFields{}, c.tail, c.fields))
			gre := pkts[0].Layer(layers.LayerTypeGRE).(*layers.GRE)
			if gre.Protocol != c.want {
				t.Fatalf("Protocol = %v,期望 %v", gre.Protocol, c.want)
			}
		})
	}
}

// TestGREProtoOverride 显式 protocol 覆盖(PPTP 0x880B):推导表外的值直接落,
// 内层是 payload_hex 也不受兜底 0x0800 干扰。
func TestGREProtoOverride(t *testing.T) {
	pkts := readPackets(t, greScenario(t, &scenario.GREFields{Protocol: hexPtr(0x880B)},
		"payload_hex", scenario.PayloadHex("0xff03002145000008"),
	))
	gre := pkts[0].Layer(layers.LayerTypeGRE).(*layers.GRE)
	if gre.Protocol != layers.EthernetType(0x880B) {
		t.Fatalf("Protocol = %#x,期望 0x880b(PPP)", gre.Protocol)
	}
}

// TestEthTypeForNotPolluted:共享推导表保持纯度 —— vlan 后跟 eth 仍报错
// (并入 eth 会让这条从报错变成静默 0x6558)。
func TestEthTypeForNotPolluted(t *testing.T) {
	s := &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
			{Type: "vlan", Fields: &scenario.VLANFields{VID: 100}},
			{Type: "eth", Fields: &scenario.EthFields{Src: "aa:bb:cc:dd:ee:01", Dst: "aa:bb:cc:dd:ee:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		},
	}}}
	// 绕过 scenario 校验直测 builder 推导报错(scenario 层另有自己的层序约束口径)
	_, err := buildPackets(s)
	if err == nil || !strings.Contains(err.Error(), "无法从下一层") {
		t.Fatalf("vlan→eth 应在推导处报错(共享表不掺 eth),得到: %v", err)
	}
}

// TestGREFieldPresence 字段写即置位并落值,gopacket 回读读回全部标志位与字段。
func TestGREFieldPresence(t *testing.T) {
	pkts := readPackets(t, greScenario(t, &scenario.GREFields{
		Key: hexPtr(0x0000a10b), Seq: u32ptr(42),
		Version: u8ptr(1), Ack: u32ptr(7),
		Recursion: u8ptr(2), Flags: u8ptr(5),
	},
		"ipv4", &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"},
	))
	gre := pkts[0].Layer(layers.LayerTypeGRE).(*layers.GRE)
	if !gre.KeyPresent || gre.Key != 0x0000a10b {
		t.Errorf("Key: present=%v value=%#x,期望 true 0xa10b", gre.KeyPresent, gre.Key)
	}
	if !gre.SeqPresent || gre.Seq != 42 {
		t.Errorf("Seq: present=%v value=%d,期望 true 42", gre.SeqPresent, gre.Seq)
	}
	if !gre.AckPresent || gre.Ack != 7 {
		t.Errorf("Ack: present=%v value=%d,期望 true 7", gre.AckPresent, gre.Ack)
	}
	if gre.Version != 1 {
		t.Errorf("Version = %d,期望 1(PPTP)", gre.Version)
	}
	if gre.RecursionControl != 2 {
		t.Errorf("Recursion = %d,期望 2", gre.RecursionControl)
	}
	// gopacket 回读把 Ack 位一并解进 Flags(Flags = data[1]>>3 含 0x80):A=1 时
	// 读回值恒比写入值多 0x10,只比低 4 位 —— 这正是 flags 值域卡 0-15 的那处位重叠
	if gre.Flags&0x0f != 5 || gre.Flags&^0x1f != 0 {
		t.Errorf("Flags = %d,期望低 4 位 = 5(A 位重叠不参与比对)", gre.Flags)
	}
	if gre.ChecksumPresent || gre.RoutingPresent {
		t.Errorf("未写字段不应置位:ChecksumPresent=%v RoutingPresent=%v", gre.ChecksumPresent, gre.RoutingPresent)
	}
}

// TestGREHeaderSize 变长头按标志位组合落对长度(§3.4 分档):
// 无字段 4 字节;K=1 → 8;K+S → 12;K+S+A(v1)→ 16;任意组合每置位一位 +4。
func TestGREHeaderSize(t *testing.T) {
	cases := []struct {
		name string
		f    *scenario.GREFields
		want int
	}{
		{"空层 4 字节", &scenario.GREFields{}, 4},
		{"K → 8 字节", &scenario.GREFields{Key: hexPtr(0x42)}, 8},
		{"K+S → 12 字节", &scenario.GREFields{Key: hexPtr(0x42), Seq: u32ptr(1)}, 12},
		{"C → 8 字节", &scenario.GREFields{ChecksumPresent: boolPtr(true)}, 8},
		{"C+K → 12 字节", &scenario.GREFields{ChecksumPresent: boolPtr(true), Key: hexPtr(0x42)}, 12},
		{"C+K+S+A 全置 → 20 字节", &scenario.GREFields{ChecksumPresent: boolPtr(true), Key: hexPtr(0x42), Seq: u32ptr(1), Ack: u32ptr(2)}, 20},
		{"K+S+A → 16 字节", &scenario.GREFields{Key: hexPtr(0x42), Seq: u32ptr(1), Ack: u32ptr(2)}, 16},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkts := readPackets(t, greScenario(t, c.f, "ipv4", &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"}))
			gre := pkts[0].Layer(layers.LayerTypeGRE).(*layers.GRE)
			if got := len(gre.Contents); got != c.want {
				t.Fatalf("GRE 头长 = %d,期望 %d", got, c.want)
			}
		})
	}
}

// TestGREChecksumAutoAndOverride checksum 三态:
// checksum_present=true 自动算出非零正确值;checksum: 0xdead 原样落、不被自动算改回。
func TestGREChecksumAutoAndOverride(t *testing.T) {
	t.Run("checksum_present 自动算", func(t *testing.T) {
		pkts := readPackets(t, greScenario(t, &scenario.GREFields{ChecksumPresent: boolPtr(true)},
			"ipv4", &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"},
		))
		gre := pkts[0].Layer(layers.LayerTypeGRE).(*layers.GRE)
		if !gre.ChecksumPresent {
			t.Fatal("ChecksumPresent 应置位")
		}
		if gre.Checksum == 0 {
			t.Fatal("自动算出的 checksum 不应为 0")
		}
		// RFC 2784 §2.1 覆盖范围 = GRE 头 + 全部载荷;gopacket 逐字节验证
		if _, v := gre.VerifyChecksum(); !v.Valid {
			t.Fatalf("自动算的 checksum 回读验证失败: actual=%#x correct=%#x", v.Actual, v.Correct)
		}
	})
	t.Run("checksum 字面值原样落", func(t *testing.T) {
		pkts := readPackets(t, greScenario(t, &scenario.GREFields{Checksum: hexPtr(0xdead)},
			"ipv4", &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"},
		))
		gre := pkts[0].Layer(layers.LayerTypeGRE).(*layers.GRE)
		if !gre.ChecksumPresent {
			t.Fatal("写 checksum 应隐含 C=1")
		}
		if gre.Checksum != 0xdead {
			t.Fatalf("Checksum = %#x,期望 0xdead(不被自动算改回)", gre.Checksum)
		}
	})
	t.Run("checksum_present:true + 字面值以值为准", func(t *testing.T) {
		pkts := readPackets(t, greScenario(t, &scenario.GREFields{ChecksumPresent: boolPtr(true), Checksum: hexPtr(0xbeef)},
			"ipv4", &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"},
		))
		gre := pkts[0].Layer(layers.LayerTypeGRE).(*layers.GRE)
		if !gre.ChecksumPresent {
			t.Fatal("并存时 C 应置位")
		}
		if gre.Checksum != 0xbeef {
			t.Fatalf("Checksum = %#x,期望 0xbeef(并存时以字面值为准,不自动算)", gre.Checksum)
		}
	})
	t.Run("C=1 + offset 落值(Reserved1 上 wire)", func(t *testing.T) {
		pkts := readPackets(t, greScenario(t, &scenario.GREFields{ChecksumPresent: boolPtr(true), Offset: hexPtr(0x1234)},
			"ipv4", &scenario.IPv4Fields{Src: "192.168.1.1", Dst: "192.168.1.2"},
		))
		gre := pkts[0].Layer(layers.LayerTypeGRE).(*layers.GRE)
		if !gre.ChecksumPresent {
			t.Fatal("offset 仅 C=1 时上 wire,C 应置位")
		}
		if gre.Offset != 0x1234 {
			t.Fatalf("Offset = %#x,期望 0x1234(Reserved1 原样落值)", gre.Offset)
		}
	})
}
