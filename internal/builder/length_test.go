package builder_test

import (
	"bytes"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 length 覆盖(两态语义)的 builder 接线,与 checksum 测试对称。
// 每层覆盖:写了 → 回读等于指定值;没写 → 自动值正确(防止误把 FixLengths 一起关掉);
// 只写一个长度字段时,同层另一个长度字段仍为公式值(锁死「一个开关控两字段」的补值逻辑)。
// 长度撒谎的包按定义无法被 gopacket 正确重组,故畸形用例只做逐字节断言、不做回读结构断言。

// ipv4LengthScenario 构造 eth/ipv4/udp/payload 包,可选给 ipv4 的 total_length/header_length 赋值。
func ipv4LengthScenario(totalLen, ihl *scenario.Hex) *scenario.Scenario {
	return &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2", Length: totalLen, IHL: ihl}},
				{Type: "udp", Fields: &scenario.UDPFields{SPort: 40000, DPort: 53}},
				{Type: "payload", Fields: &scenario.PayloadFields{Payload: "probe"}},
			},
		}},
	}
}

// TestIPv4LengthOverride 显式写 total_length=9999 → 原样上 wire,ihl 未写仍为 5(公式值)。
// 这是「一个开关控两字段」补值逻辑的核心用例:只让 length 撒谎,ihl 保持正确。
func TestIPv4LengthOverride(t *testing.T) {
	s := ipv4LengthScenario(hexPtr(9999), nil)
	pkts := readPackets(t, buildScenarioPcap(t, s))
	ip := pkts[0].Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip.Length != 9999 {
		t.Fatalf("ipv4 total_length = %d,期望 9999(显式覆盖原样落值)", ip.Length)
	}
	if ip.IHL != 5 {
		t.Fatalf("ipv4 header_length = %d,期望 5(未覆盖应补公式值,不应连 IHL 一起归零)", ip.IHL)
	}
}

// TestIPv4IHLOverride 显式写 header_length=0xF → 原样上 wire,total_length 未写仍为公式值。
func TestIPv4IHLOverride(t *testing.T) {
	s := ipv4LengthScenario(nil, hexPtr(0xF))
	pkts := readPackets(t, buildScenarioPcap(t, s))
	ip := pkts[0].Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip.IHL != 0xF {
		t.Fatalf("ipv4 header_length = %d,期望 0xF(显式覆盖原样落值)", ip.IHL)
	}
	// total_length 未覆盖 → 公式值 = 整包字节(20 头 + 8 udp + 5 payload = 33)。
	if ip.Length != 33 {
		t.Fatalf("ipv4 total_length = %d,期望 33(未覆盖应补公式值)", ip.Length)
	}
}

// TestIPv4LengthZero 显式写 total_length=0 → wire 字节偏移 2-4 处落 0(两态语义:写即覆盖,0 是合法畸形)。
// 不做回读结构断言:gopacket 解码会把 Length=0 当 TSO 重设为实际长度(见 ip4.go DecodeFromBytes),
// 回读 ip.Length 必非 0 —— 故只断言 wire 字节,与「畸形包不做回读断言」原则一致。
func TestIPv4LengthZero(t *testing.T) {
	s := ipv4LengthScenario(hexPtr(0), nil)
	pkts := readPackets(t, buildScenarioPcap(t, s))
	raw := pkts[0].Data()
	// eth 14 字节后是 ipv4;ipv4 Length 在偏移 2-4。
	got := uint16(raw[16])<<8 | uint16(raw[17])
	if got != 0 {
		t.Fatalf("wire ipv4 total_length = %d,期望 0(显式 0 原样落值)", got)
	}
}

// TestIPv4LengthAuto 未写任何长度字段 → 自动值正确(与现状逐字节一致,FixLengths 未被误关)。
func TestIPv4LengthAuto(t *testing.T) {
	s := ipv4LengthScenario(nil, nil)
	pkts := readPackets(t, buildScenarioPcap(t, s))
	ip := pkts[0].Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip.Length != 33 {
		t.Fatalf("ipv4 total_length = %d,期望 33(自动计算)", ip.Length)
	}
	if ip.IHL != 5 {
		t.Fatalf("ipv4 header_length = %d,期望 5(自动计算)", ip.IHL)
	}
}

// --- UDP ---

func udpLengthScenario(udpLen *scenario.Hex) *scenario.Scenario {
	return &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "udp", Fields: &scenario.UDPFields{SPort: 40000, DPort: 53, Length: udpLen}},
				{Type: "payload", Fields: &scenario.PayloadFields{Payload: "probe"}},
			},
		}},
	}
}

// TestUDPLengthOverride 显式写 udp.total_length=1234 → 原样上 wire。
func TestUDPLengthOverride(t *testing.T) {
	s := udpLengthScenario(hexPtr(1234))
	pkts := readPackets(t, buildScenarioPcap(t, s))
	udp := pkts[0].Layer(layers.LayerTypeUDP).(*layers.UDP)
	if udp.Length != 1234 {
		t.Fatalf("udp length = %d,期望 1234(显式覆盖原样落值)", udp.Length)
	}
}

// TestUDPLengthAuto 未写 → 自动值 = 8(头) + 5(payload) = 13。
func TestUDPLengthAuto(t *testing.T) {
	s := udpLengthScenario(nil)
	pkts := readPackets(t, buildScenarioPcap(t, s))
	udp := pkts[0].Layer(layers.LayerTypeUDP).(*layers.UDP)
	if udp.Length != 13 {
		t.Fatalf("udp length = %d,期望 13(自动计算)", udp.Length)
	}
}

// --- TCP ---

func tcpLengthScenario(dataOff *scenario.Hex, mss *uint16) *scenario.Scenario {
	return &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 40000, DPort: 80, Flags: []string{"SYN"}, DataOffset: dataOff, MSS: mss}},
			},
		}},
	}
}

// TestTCPDataOffsetOverride 显式写 tcp.header_length=15 → 原样上 wire。
func TestTCPDataOffsetOverride(t *testing.T) {
	s := tcpLengthScenario(hexPtr(15), nil)
	pkts := readPackets(t, buildScenarioPcap(t, s))
	tcp := pkts[0].Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcp.DataOffset != 15 {
		t.Fatalf("tcp data_offset = %d,期望 15(显式覆盖原样落值)", tcp.DataOffset)
	}
}

// TestTCPDataOffsetAutoNoOption 无 option → 自动 data_offset=5(20 字节头 / 4)。
func TestTCPDataOffsetAutoNoOption(t *testing.T) {
	s := tcpLengthScenario(nil, nil)
	pkts := readPackets(t, buildScenarioPcap(t, s))
	tcp := pkts[0].Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcp.DataOffset != 5 {
		t.Fatalf("tcp data_offset = %d,期望 5(无 option 自动计算)", tcp.DataOffset)
	}
}

// TestTCPDataOffsetAutoMSS 有 MSS option(4 字节,无 padding)→ 自动 data_offset=6。
// 锁死「只写 data_offset 时 MSS option 仍完整、padding 正确」的补值逻辑。
func TestTCPDataOffsetAutoMSS(t *testing.T) {
	mss := uint16(1460)
	s := tcpLengthScenario(nil, &mss)
	pkts := readPackets(t, buildScenarioPcap(t, s))
	tcp := pkts[0].Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcp.DataOffset != 6 {
		t.Fatalf("tcp data_offset = %d,期望 6(20 + 4 MSS,无 padding)", tcp.DataOffset)
	}
}

// --- IPv6 ---

func ipv6LengthScenario(payloadLen *scenario.Hex) *scenario.Scenario {
	return &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv6", Fields: &scenario.IPv6Fields{Src: "::1", Dst: "::2", PayloadLength: payloadLen}},
				{Type: "udp", Fields: &scenario.UDPFields{SPort: 40000, DPort: 53}},
				{Type: "payload", Fields: &scenario.PayloadFields{Payload: "probe"}},
			},
		}},
	}
}

// TestIPv6PayloadLengthOverride 显式写 payload_length=9999 → 原样上 wire。
func TestIPv6PayloadLengthOverride(t *testing.T) {
	s := ipv6LengthScenario(hexPtr(9999))
	pkts := readPackets(t, buildScenarioPcap(t, s))
	ip := pkts[0].Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if ip.Length != 9999 {
		t.Fatalf("ipv6 payload_length = %d,期望 9999(显式覆盖原样落值)", ip.Length)
	}
}

// TestIPv6PayloadLengthAuto 未写 → 自动值 = 8(udp 头) + 5(payload) = 13(不含 40B ipv6 头)。
func TestIPv6PayloadLengthAuto(t *testing.T) {
	s := ipv6LengthScenario(nil)
	pkts := readPackets(t, buildScenarioPcap(t, s))
	ip := pkts[0].Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if ip.Length != 13 {
		t.Fatalf("ipv6 payload_length = %d,期望 13(自动计算,不含 40B 头)", ip.Length)
	}
}

// --- 跨层耦合(锁死方案第 4 点实测结论,防止后人"优化"掉) ---

// TestIPv4LengthLieDoesNotAffectUDPChecksum: ipv4.total_length 撒谎(33→9999)+ UDP checksum 自动
// → UDP checksum 与不撒谎时逐字节相同(伪首部长度取实际字节数,不读 ip.Length 字段)。
func TestIPv4LengthLieDoesNotAffectUDPChecksum(t *testing.T) {
	// 不撒谎的基线。
	base := udpLengthScenario(nil)
	basePkt := readPackets(t, buildScenarioPcap(t, base))[0]
	baseUDP := basePkt.Layer(layers.LayerTypeUDP).(*layers.UDP)

	// ipv4 撒谎但 udp 不撒谎:udp 用 ipv4LengthScenario(它也含 udp/payload)。
	s := ipv4LengthScenario(hexPtr(9999), nil)
	pkts := readPackets(t, buildScenarioPcap(t, s))
	udp := pkts[0].Layer(layers.LayerTypeUDP).(*layers.UDP)

	if udp.Checksum != baseUDP.Checksum {
		t.Fatalf("ipv4 length 撒谎不应改变 udp checksum: got=%#x want=%#x", udp.Checksum, baseUDP.Checksum)
	}
}

// TestUDPLengthLieChangesUDPChecksum: udp.total_length 撒谎(13→1234)+ UDP checksum 自动
// → UDP checksum 改变(udp.Length 字节本身在逐字节求和范围内,故同层污染)。
// 与 TestIPv4LengthLieDoesNotAffectUDPChecksum 对照,锁死「跨层不污染、同层污染」。
func TestUDPLengthLieChangesUDPChecksum(t *testing.T) {
	base := udpLengthScenario(nil)
	basePkt := readPackets(t, buildScenarioPcap(t, base))[0]
	baseUDP := basePkt.Layer(layers.LayerTypeUDP).(*layers.UDP)

	s := udpLengthScenario(hexPtr(1234))
	pkts := readPackets(t, buildScenarioPcap(t, s))
	udp := pkts[0].Layer(layers.LayerTypeUDP).(*layers.UDP)

	if udp.Checksum == baseUDP.Checksum {
		t.Fatalf("udp length 撒谎应改变 udp checksum: got=%#x == base=%#x", udp.Checksum, baseUDP.Checksum)
	}
	if udp.Length != 1234 {
		t.Fatalf("udp length = %d,期望 1234(撒谎值原样上 wire)", udp.Length)
	}
}

// TestMalformedLengthPacketByteStable 长度撒谎包只做逐字节 golden 比对(确定性),
// 不做回读结构断言。此处用一个固定 scenario 验证两次构建字节一致(确定性)。
func TestMalformedLengthPacketByteStable(t *testing.T) {
	s := ipv4LengthScenario(hexPtr(9999), nil)
	b1 := buildScenarioPcap(t, s)
	b2 := buildScenarioPcap(t, s)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("同一 scenario 两次构建字节不一致(确定性破坏)")
	}
}

// TestIPv4LengthLieHeaderChecksumRecomputed: ipv4.total_length 撒谎但未显式覆盖 checksum
// → IPv4 header checksum 必须被正确重算(覆盖撒谎后的 Length 字节)。ComputeChecksums 仍开,
// gopacket 对整个已序列化的 IP 头(含撒谎的 Length)求和,故 checksum 与不撒谎时不同、
// 且对该撒谎头自洽(VerifyChecksum 通过)。锁死「length 覆盖只关 FixLengths、不关
// ComputeChecksums」,防止后人误把 IPv4 的 checksum 计算也一起关掉,产出 Length 与
// checksum 互相矛盾的畸形包(撒谎长度却带一个按真实长度算的旧 checksum)。
func TestIPv4LengthLieHeaderChecksumRecomputed(t *testing.T) {
	s := ipv4LengthScenario(hexPtr(9999), nil)
	pkts := readPackets(t, buildScenarioPcap(t, s))
	ip := pkts[0].Layer(layers.LayerTypeIPv4).(*layers.IPv4)

	if ip.Length != 9999 {
		t.Fatalf("ipv4 total_length = %d,期望 9999", ip.Length)
	}
	// checksum 必须是针对撒谎头重算的结果,而非零或旧值。
	if ip.Checksum == 0 {
		t.Fatalf("ipv4 header checksum = 0,期望针对撒谎长度重算非零")
	}
	// VerifyChecksum 用 ip.Contents(已按 IHL 截取的 wire 头字节,含撒谎 Length)重算,
	// 通过即证明 checksum 与撒谎头自洽。注意:Length=9999 比 wire 实际字节数大,
	// gopacket 解码会截断/告警,但 Contents 仍是 IHL*4 字节的头,校验和验证不受影响。
	if _, v := ip.VerifyChecksum(); !v.Valid {
		t.Fatalf("ipv4 header checksum 对撒谎头不自洽: %#x != 重算 %#x", v.Actual, v.Correct)
	}

	// 对照:不撒谎的基线 checksum 必须与撒谎包不同(Length 字节变了,求和结果必然变)。
	base := readPackets(t, buildScenarioPcap(t, ipv4LengthScenario(nil, nil)))[0]
	baseIP := base.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip.Checksum == baseIP.Checksum {
		t.Fatalf("撒谎长度应改变 ipv4 header checksum: got=%#x == base=%#x", ip.Checksum, baseIP.Checksum)
	}
}

// TestTCPDataOffsetLieChangesTCPChecksum: tcp.header_length 撒谎(6→15)+ TCP checksum 自动
// → TCP checksum 改变(DataOffset 位在 TCP 头 bytes[12] 高 4 位,被 computeChecksum
// 逐字节求和覆盖,故同层污染)。与 TestUDPLengthLieChangesUDPChecksum 对称,锁死
// 「同层长度撒谎污染本层 checksum」在 TCP 侧也成立,防止后人误以为 DataOffset
// 是独立字段、不会影响 checksum。
func TestTCPDataOffsetLieChangesTCPChecksum(t *testing.T) {
	mss := uint16(1460)
	// 不撒谎的基线:MSS option → data_offset=6,checksum 自动。
	basePkt := readPackets(t, buildScenarioPcap(t, tcpLengthScenario(nil, &mss)))[0]
	baseTCP := basePkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if baseTCP.DataOffset != 6 {
		t.Fatalf("基线 tcp data_offset = %d,期望 6", baseTCP.DataOffset)
	}

	// data_offset 撒谎成 15(0xF),checksum 仍自动。
	s := tcpLengthScenario(hexPtr(15), &mss)
	pkts := readPackets(t, buildScenarioPcap(t, s))
	tcp := pkts[0].Layer(layers.LayerTypeTCP).(*layers.TCP)

	if tcp.DataOffset != 15 {
		t.Fatalf("tcp data_offset = %d,期望 15(撒谎值原样上 wire)", tcp.DataOffset)
	}
	if tcp.Checksum == baseTCP.Checksum {
		t.Fatalf("tcp header_length 撒谎应改变 tcp checksum: got=%#x == base=%#x", tcp.Checksum, baseTCP.Checksum)
	}
}

// 引用 gopacket 包以保留 import(部分用例仅用 layers)。
var _ = gopacket.Default
