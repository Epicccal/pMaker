package builder_test

import (
	"strings"
	"testing"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 ipv4 checksum 两态覆盖:写了 → 回读等于指定值;没写 → 自动计算非零且正确。

// hexPtr 取 scenario.Hex 指针,供 *Hex 字段构造。
func hexPtr(v scenario.Hex) *scenario.Hex { return &v }

// ipv4ChecksumScenario 构造一个 eth/ipv4/udp/payload 包,可选给 ipv4.Checksum 赋值。
func ipv4ChecksumScenario(ipv4Checksum *scenario.Hex, udpChecksum *scenario.Hex) *scenario.Scenario {
	return &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", Checksum: ipv4Checksum}},
				{Type: "udp", Fields: &scenario.UDPFields{SPort: 40000, DPort: 53, Checksum: udpChecksum}},
				{Type: "payload", Fields: &scenario.PayloadFields{Payload: "probe"}},
			},
		}},
	}
}

// TestIPv4ChecksumOverride 显式写 0xdead → 回读等于 0xdead(关闭自动计算,值原样上 wire)。
func TestIPv4ChecksumOverride(t *testing.T) {
	s := ipv4ChecksumScenario(hexPtr(0xdead), nil)
	pkts := readPackets(t, buildScenarioPcap(t, s))
	if len(pkts) != 1 {
		t.Fatalf("期望 1 个包,得到 %d", len(pkts))
	}
	ipL := pkts[0].Layer(layers.LayerTypeIPv4)
	if ipL == nil {
		t.Fatal("缺少 IPv4 层")
	}
	ip := ipL.(*layers.IPv4)
	if ip.Checksum != 0xdead {
		t.Fatalf("ipv4 checksum = %#x,期望 0xdead(显式覆盖应原样落值)", ip.Checksum)
	}
}

// TestIPv4ChecksumAuto 未写 checksum → 自动计算,结果非零且 gopacket 校验通过(防止
// 接线时误把自动计算一起关掉)。
func TestIPv4ChecksumAuto(t *testing.T) {
	s := ipv4ChecksumScenario(nil, nil)
	pkts := readPackets(t, buildScenarioPcap(t, s))
	if len(pkts) != 1 {
		t.Fatalf("期望 1 个包,得到 %d", len(pkts))
	}
	ip := pkts[0].Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip.Checksum == 0 {
		t.Fatalf("ipv4 checksum=0,期望自动计算非零")
	}
}

// TestIPv4AndUDPChecksumBothOverride 同包 ipv4 + udp 各自显式覆盖 checksum → 两个值都
// 原样上 wire、互不干扰(锁死「每层 opts 独立」的接线:关掉某一层 ComputeChecksums 不应
// 顺带影响另一层)。这是 ipv4ChecksumScenario 的 udpChecksum 形参存在的理由。
func TestIPv4AndUDPChecksumBothOverride(t *testing.T) {
	s := ipv4ChecksumScenario(hexPtr(0xdead), hexPtr(0x1234))
	pkts := readPackets(t, buildScenarioPcap(t, s))
	if len(pkts) != 1 {
		t.Fatalf("期望 1 个包,得到 %d", len(pkts))
	}
	ip := pkts[0].Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip.Checksum != 0xdead {
		t.Fatalf("ipv4 checksum = %#x,期望 0xdead(应不受 udp 覆盖影响)", ip.Checksum)
	}
	udp := pkts[0].Layer(layers.LayerTypeUDP).(*layers.UDP)
	if udp.Checksum != 0x1234 {
		t.Fatalf("udp checksum = %#x,期望 0x1234(应不受 ipv4 覆盖影响)", udp.Checksum)
	}
}

// TestIPProtoOverrideNumericRejected 显式覆盖写数字(protocol: "47")须报错,且文案
// 走覆盖路径 —— 用户已写覆盖字段,指引不能再指向「请显式写 protocol」(循环指引)。
func TestIPProtoOverrideNumericRejected(t *testing.T) {
	s := ipv4ProtoScenario("47")
	_, err := buildPackets(s)
	if err == nil {
		t.Fatal("protocol: \"47\" 应报错(覆盖只认名字),却成功出包")
	}
	if !strings.Contains(err.Error(), "覆盖值") {
		t.Fatalf("报错应是覆盖路径文案(含「覆盖值」),得到: %v", err)
	}
	if strings.Contains(err.Error(), "请显式写 protocol") {
		t.Fatalf("覆盖路径报错不应再指引「请显式写 protocol」(循环指引),得到: %v", err)
	}
}

// TestIPProtoOverrideUnknownNameRejected 覆盖写推导表外的名字(sctp)同样报错。
func TestIPProtoOverrideUnknownNameRejected(t *testing.T) {
	s := ipv4ProtoScenario("sctp")
	if _, err := buildPackets(s); err == nil {
		t.Fatal("protocol: \"sctp\" 应报错(不在推导表内),却成功出包")
	}
}

// TestIPProtoOverrideValidName 推导表内的名字(sctp 反例对照:gre)覆盖照常生效。
func TestIPProtoOverrideValidName(t *testing.T) {
	s := ipv4ProtoScenario("gre")
	pkts := readPackets(t, buildScenarioPcap(t, s))
	ip := pkts[0].Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip.Protocol != layers.IPProtocolGRE {
		t.Fatalf("protocol 覆盖 = %v,期望 47(GRE)", ip.Protocol)
	}
}

// ipv4ProtoScenario 构造 eth → ipv4(带 protocol 覆盖)→ payload 场景。
func ipv4ProtoScenario(proto string) *scenario.Scenario {
	return &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", Protocol: protoPtr(proto)}},
				{Type: "payload", Fields: &scenario.PayloadFields{Payload: "x"}},
			},
		}},
	}
}

// protoPtr 取 string 指针,供 *string 覆盖字段构造。
func protoPtr(v string) *string { return &v }

// ---------- next-proto 推导与覆盖(新错误分支) ----------

// ipNextScenario 构造 eth → <ip 层>(可选 next_header/protocol 覆盖)→ <tail 层> 场景。
func ipNextScenario(ipLayer string, override *string, tailType string, tailFields any) *scenario.Scenario {
	var fields any
	var tf any
	if override != nil {
		if ipLayer == "ipv4" {
			fields = &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", Protocol: override}
		} else {
			fields = &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2", NextHeader: override}
		}
	} else if ipLayer == "ipv4" {
		fields = &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}
	} else {
		fields = &scenario.IPv6Fields{Src: "2001:db8::1", Dst: "2001:db8::2"}
	}
	if tailFields != nil {
		tf = tailFields
	} else {
		tf = &scenario.PayloadFields{Payload: "x"}
	}
	return &scenario.Scenario{LinkType: "ethernet", Packets: []scenario.Packet{{Stack: []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
		{Type: ipLayer, Fields: fields},
		{Type: tailType, Fields: tf},
	}}}}
}

// telnetLayer 合法 telnet 层(纯 NVT 文本),作推导表外的结构化下一层。
func telnetLayer() any {
	return &scenario.TelnetFields{Args: "hi"}
}

// TestIPv4ProtoDerivationRejected ipv4 后接推导表外的结构化层(telnet)→ 报错,
// 不再静默落 6。l2_test 覆盖 eth/vlan 侧;此处补 IP 侧。
func TestIPv4ProtoDerivationRejected(t *testing.T) {
	s := ipNextScenario("ipv4", nil, "telnet", telnetLayer())
	if _, err := buildPackets(s); err == nil {
		t.Fatal("ipv4→telnet 应报错(无法推导协议号),却成功出包")
	}
}

// TestIPv6NextHeaderDerivationRejected 同上,ipv6 侧。
func TestIPv6NextHeaderDerivationRejected(t *testing.T) {
	s := ipNextScenario("ipv6", nil, "telnet", telnetLayer())
	if _, err := buildPackets(s); err == nil {
		t.Fatal("ipv6→telnet 应报错(无法推导 next-header),却成功出包")
	}
}

// TestIPv6NextHeaderOverrideError ipv6.next_header 写数字("43")→ 覆盖路径报错,
// 同样不循环指引「请显式写」。
func TestIPv6NextHeaderOverrideError(t *testing.T) {
	nh := "43"
	s := ipNextScenario("ipv6", &nh, "payload", nil)
	_, err := buildPackets(s)
	if err == nil {
		t.Fatal("next_header: \"43\" 应报错(覆盖只认名字),却成功出包")
	}
	if !strings.Contains(err.Error(), "覆盖值") {
		t.Fatalf("报错应是覆盖路径文案(含「覆盖值」),得到: %v", err)
	}
	if strings.Contains(err.Error(), "请显式写") {
		t.Fatalf("覆盖路径报错不应再指引「请显式写」(循环指引),得到: %v", err)
	}
}

// TestIPProtoTerminalDefaultTCP 末层/payload/payload_hex 保留缺省 TCP(6),
// 推导报错不误伤 raw 尾巴惯例。
func TestIPProtoTerminalDefaultTCP(t *testing.T) {
	for _, tail := range []struct {
		typ    string
		fields any
	}{
		{"payload", &scenario.PayloadFields{Payload: "x"}},
		{"payload_hex", scenario.PayloadHex("0xdeadbeef")},
	} {
		s := ipNextScenario("ipv4", nil, tail.typ, tail.fields)
		pkts := readPackets(t, buildScenarioPcap(t, s))
		ip := pkts[0].Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if ip.Protocol != layers.IPProtocolTCP {
			t.Fatalf("ipv4 后接 %s,protocol = %v,期望 6(TCP 惯例缺省)", tail.typ, ip.Protocol)
		}
	}
}
