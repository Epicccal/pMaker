package builder_test

import (
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// L2(eth/vlan)构造:EtherType/TPID 推导与两态覆盖、next-proto 推导报错语义。
// derivationStack 构造 eth|vlan → <mid> → <tail> 的单包场景。
//
// 注意:tail 层只贡献 Type 字符串给推导(next = stack[j+1].Type),Fields 恒为
// PayloadFields —— 即使 Type 写 "ipv4" 也不是真 IPv4 层。报错类测试(推导失败)在
// builder 触碰 tail 前就已返回,无影响;但**成功类测试**(如显式覆盖后整包序列化)里
// tail 会以 payload 字节落 wire,Type 必须在推导表内才不会误触推导报错。只给 mid 侧
// 的 gre/ipv4 等层挂真实 Fields;勿把本 helper 扩到 mid="ipv4" 等会真实序列化 tail 的
// 场景(那里需要真 IPv4Fields,见 ip_test.go 的 ipNextScenario)。
func derivationStack(mid, tail string) *scenario.Scenario {
	stack := []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
	}
	if mid == "vlan" {
		stack = append(stack, scenario.Layer{Type: "vlan", Fields: &scenario.VLANFields{VID: 100}})
	}
	stack = append(stack, scenario.Layer{Type: mid, Fields: &scenario.GREFields{}})
	if tail != "" {
		stack = append(stack, scenario.Layer{Type: tail, Fields: &scenario.PayloadFields{Payload: "x"}})
	}
	return &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{Stack: stack}}}
}

func TestEthToGRERejected(t *testing.T) {
	s := derivationStack("gre", "ipv4") // eth → gre → ipv4
	_, err := buildPackets(s)
	if err == nil {
		t.Fatal("eth→gre 应报错(无法推导 EtherType),却成功出包")
	}
	if !strings.Contains(err.Error(), "gre") {
		t.Fatalf("报错应指向下一层 gre,得到: %v", err)
	}
}

func TestVLANToGRERejected(t *testing.T) {
	s := derivationStack("vlan", "gre") // eth → vlan → gre → payload
	_, err := buildPackets(s)
	if err == nil {
		t.Fatal("vlan→gre 应报错(无法推导 EtherType),却成功出包")
	}
}

// TestExplicitOverrideStillAllowed 推导报错不拦截显式覆盖:eth.ethertype 写死即可
// 构造 eth→gre(故意断链合法)。eth→gre 直挂在 scenario 层被 validateGREPosition 拒
// (GRE 须由 IP 协议 47 承载),这里绕过 Validate 直测 builder 的覆盖语义。
func TestExplicitOverrideStillAllowed(t *testing.T) {
	s := derivationStack("gre", "ipv4")
	eth := s.Packets[0].Stack[0].Fields.(*scenario.EthFields)
	et := scenario.Hex(0x0800)
	eth.EtherType = &et
	if _, err := buildPackets(s); err != nil {
		t.Fatalf("显式 ethertype 覆盖后不应报错: %v", err)
	}
}

// 自动推导:eth→vlan 得 0x8100,vlan→ipv4 得 0x0800。
func TestEthEtherTypeAuto(t *testing.T) {
	s := &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{Stack: []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
		{Type: "vlan", Fields: &scenario.VLANFields{VID: 100}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}},
	}}}}
	pkts := readPackets(t, buildScenarioPcap(t, s))
	eth := pkts[0].Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if eth.EthernetType != layers.EthernetTypeDot1Q {
		t.Fatalf("eth 后接 vlan,EthernetType = %#x,期望 0x8100(Dot1Q)", eth.EthernetType)
	}
	vlan := pkts[0].Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
	if vlan.Type != layers.EthernetTypeIPv4 {
		t.Fatalf("vlan 后接 ipv4,Type = %#x,期望 0x0800", vlan.Type)
	}
}

// eth.ethertype 显式写死 → 原样上 wire(两态覆盖)。
func TestEthEtherTypeOverride(t *testing.T) {
	et := scenario.Hex(0x1234)
	s := &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{Stack: []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb", EtherType: &et}},
		{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}},
	}}}}
	pkts := readPackets(t, buildScenarioPcap(t, s))
	eth := pkts[0].Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if eth.EthernetType != 0x1234 {
		t.Fatalf("eth.ethertype = %#x,期望 0x1234(显式覆盖应原样落值)", eth.EthernetType)
	}
}

// QinQ 自动串接:外层 vlan→内层 vlan 得 0x8100,内层→ipv4 得 0x0800。
func TestVLANQinQAutoDerive(t *testing.T) {
	s := &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{Stack: []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
		{Type: "vlan", Fields: &scenario.VLANFields{VID: 100}}, // S-TAG
		{Type: "vlan", Fields: &scenario.VLANFields{VID: 200}}, // C-TAG
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}},
	}}}}
	pkts := readPackets(t, buildScenarioPcap(t, s))
	dot1qs := layersOfType[*layers.Dot1Q](pkts[0])
	if len(dot1qs) != 2 {
		t.Fatalf("期望 2 层 Dot1Q(QinQ),得到 %d", len(dot1qs))
	}
	if dot1qs[0].VLANIdentifier != 100 || dot1qs[1].VLANIdentifier != 200 {
		t.Fatalf("VID 顺序错:外层 %d 内层 %d,期望 100/200", dot1qs[0].VLANIdentifier, dot1qs[1].VLANIdentifier)
	}
	if dot1qs[0].Type != layers.EthernetTypeDot1Q {
		t.Fatalf("外层 S-TAG Type = %#x,期望 0x8100(后接内层 vlan)", dot1qs[0].Type)
	}
	if dot1qs[1].Type != layers.EthernetTypeIPv4 {
		t.Fatalf("内层 C-TAG Type = %#x,期望 0x0800(后接 ipv4)", dot1qs[1].Type)
	}
}

// vlan.type 显式写死(非标 0x9100)→ 原样上 wire;gopacket 只认 0x8100/0x88a8,
// 内层不再解出。type 语义是「本层标签后的 TPID/EtherType」,非标值是合法构造意图。
func TestVLANTypeNonStandardTPID(t *testing.T) {
	tpid := scenario.Hex(0x9100)
	s := &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{Stack: []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
		{Type: "vlan", Fields: &scenario.VLANFields{VID: 100, Type: &tpid}}, // 外层,后接内层 vlan
		{Type: "vlan", Fields: &scenario.VLANFields{VID: 200}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}},
	}}}}
	pkts := readPackets(t, buildScenarioPcap(t, s))
	dot1qs := layersOfType[*layers.Dot1Q](pkts[0])
	if len(dot1qs) != 1 {
		t.Fatalf("期望 1 层 Dot1Q 可解(非标 TPID 内层 gopacket 不再解出),得到 %d", len(dot1qs))
	}
	if dot1qs[0].Type != 0x9100 {
		t.Fatalf("外层 vlan Type = %#x,期望 0x9100(type 显式覆盖应原样落值)", dot1qs[0].Type)
	}
	if dot1qs[0].VLANIdentifier != 100 {
		t.Fatalf("VID = %d,期望 100", dot1qs[0].VLANIdentifier)
	}
}

// vlan.type=0xffff 原样落值;gopacket 特判 0xffff 为 EthernetTypeRaw(Raw IP),回读链不断。
func TestVLANTypeOverrideBreaksChain(t *testing.T) {
	br := scenario.Hex(0xffff)
	s := &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{Stack: []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
		{Type: "vlan", Fields: &scenario.VLANFields{VID: 100, Type: &br}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}},
	}}}}
	pkts := readPackets(t, buildScenarioPcap(t, s))
	vlan := pkts[0].Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
	if vlan.Type != 0xffff {
		t.Fatalf("vlan.type = %#x,期望 0xffff(显式覆盖应原样落值)", vlan.Type)
	}
}

// 真·断链:type=0x1234(未知 EtherType)→ gopacket 回读静默停链,IPv4 不再解出。
func TestVLANTypeOverrideTrueBreak(t *testing.T) {
	br := scenario.Hex(0x1234)
	s := &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{Stack: []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
		{Type: "vlan", Fields: &scenario.VLANFields{VID: 100, Type: &br}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}},
	}}}}
	pkts := readPackets(t, buildScenarioPcap(t, s))
	vlan := pkts[0].Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
	if vlan.Type != 0x1234 {
		t.Fatalf("vlan.type = %#x,期望 0x1234(显式覆盖应原样落值)", vlan.Type)
	}
	if pkts[0].Layer(layers.LayerTypeIPv4) != nil {
		t.Fatal("type=0x1234 后 gopacket 不应解出 IPv4 层(断链)")
	}
	if pkts[0].ErrorLayer() != nil {
		t.Fatal("未知 EtherType 应静默停链(LayerTypeZero),而非 DecodeFailure")
	}
}

// layersOfType 收集包中某层所有实例(按出现顺序),供 QinQ 多层断言。
func layersOfType[T gopacket.Layer](p gopacket.Packet) []T {
	var out []T
	for _, l := range p.Layers() {
		if v, ok := l.(T); ok {
			out = append(out, v)
		}
	}
	return out
}

// vlan.pri / vlan.dei 落 TCI 高 4 位:gopacket 序列化 TCI = pri<<13 | dei<<12 | vid,
// 回读断言 Priority/DropEligible 原样还原。
func TestVLANPriAndDEI(t *testing.T) {
	pri := uint8(5)
	deiTrue := true
	s := &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{Stack: []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
		{Type: "vlan", Fields: &scenario.VLANFields{VID: 100, Pri: &pri, DEI: &deiTrue}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}},
	}}}}
	pkts := readPackets(t, buildScenarioPcap(t, s))
	vlan := pkts[0].Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
	if vlan.Priority != 5 {
		t.Fatalf("PCP = %d,期望 5", vlan.Priority)
	}
	if !vlan.DropEligible {
		t.Fatal("DEI 应为 true")
	}
	if vlan.VLANIdentifier != 100 {
		t.Fatalf("VID = %d,期望 100(pri/dei 不得侵占 vid 位)", vlan.VLANIdentifier)
	}
}

// 缺省(不写 pri/dei)时 TCI 高 4 位为 0,与既有行为一致。
func TestVLANPriDEIDefaultZero(t *testing.T) {
	s := &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{Stack: []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
		{Type: "vlan", Fields: &scenario.VLANFields{VID: 100}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
		{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}},
	}}}}
	pkts := readPackets(t, buildScenarioPcap(t, s))
	vlan := pkts[0].Layer(layers.LayerTypeDot1Q).(*layers.Dot1Q)
	if vlan.Priority != 0 || vlan.DropEligible {
		t.Fatalf("缺省应 PCP=0/DEI=false,得到 pri=%d dei=%v", vlan.Priority, vlan.DropEligible)
	}
}
