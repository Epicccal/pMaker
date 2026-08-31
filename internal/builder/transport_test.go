package builder_test

import (
	"testing"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 tcp/udp checksum 两态覆盖:
//   - tcp:写了 → 回读等于指定值;没写 → 自动计算非零
//   - udp:写了非零 → 回读等于指定值;写了 0 → 回读等于 0(不被 0xffff 翻转)且 length 正确
//
// UDP 的 0xffff 翻转只在 ComputeChecksums=true 时发生;覆盖层关掉计算后 u.Checksum=0
// 原样上 wire。u.Length 在独立的 FixLengths 块里填充,不受 ComputeChecksums 影响 ——
// 这两个用例锁死「不动 FixLengths」的前提。

// tcpChecksumScenario 构造 eth/ipv4/tcp(SYN) 包,可选给 tcp.Checksum 赋值。
func tcpChecksumScenario(csum *scenario.Hex) *scenario.Scenario {
	return &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 40000, DPort: 80, Flags: []string{"SYN"}, Checksum: csum}},
			},
		}},
	}
}

// udpChecksumScenario 构造 eth/ipv4/udp/payload 包,可选给 udp.Checksum 赋值。
func udpChecksumScenario(csum *scenario.Hex) *scenario.Scenario {
	return &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "udp", Fields: &scenario.UDPFields{SPort: 40000, DPort: 53, Checksum: csum}},
				{Type: "payload", Fields: &scenario.PayloadFields{Payload: "probe"}},
			},
		}},
	}
}

func TestTCPChecksumOverride(t *testing.T) {
	s := tcpChecksumScenario(hexPtr(0xdead))
	pkts := readPackets(t, buildScenarioPcap(t, s))
	tcp := pkts[0].Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcp.Checksum != 0xdead {
		t.Fatalf("tcp checksum = %#x,期望 0xdead", tcp.Checksum)
	}
}

func TestTCPChecksumAuto(t *testing.T) {
	s := tcpChecksumScenario(nil)
	pkts := readPackets(t, buildScenarioPcap(t, s))
	tcp := pkts[0].Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcp.Checksum == 0 {
		t.Fatalf("tcp checksum=0,期望自动计算非零")
	}
}

// TestUDPChecksumOverrideNonZero 显式写 0x1234 → 回读等于 0x1234。
func TestUDPChecksumOverrideNonZero(t *testing.T) {
	s := udpChecksumScenario(hexPtr(0x1234))
	pkts := readPackets(t, buildScenarioPcap(t, s))
	udp := pkts[0].Layer(layers.LayerTypeUDP).(*layers.UDP)
	if udp.Checksum != 0x1234 {
		t.Fatalf("udp checksum = %#x,期望 0x1234", udp.Checksum)
	}
	// length 由 FixLengths 自动填充:UDP 头 8 + payload 5 = 13。
	if udp.Length != 13 {
		t.Fatalf("udp length = %d,期望 13(FixLengths 仍生效)", udp.Length)
	}
}

// TestUDPChecksumZero 显式写 0 → 回读等于 0(不被 0xffff 翻转)且 length 正确。
// 这是 UDP 独有的注意点:RFC 768 下 0xffff 翻转只在自动计算时发生,覆盖层关掉计算后
// 字面 0 原样上 wire。锁死「覆盖层不动 FixLengths」这个前提。
func TestUDPChecksumZero(t *testing.T) {
	s := udpChecksumScenario(hexPtr(0))
	pkts := readPackets(t, buildScenarioPcap(t, s))
	udp := pkts[0].Layer(layers.LayerTypeUDP).(*layers.UDP)
	if udp.Checksum != 0 {
		t.Fatalf("udp checksum = %#x,期望 0(不应被 0xffff 翻转)", udp.Checksum)
	}
	if udp.Length != 13 {
		t.Fatalf("udp length = %d,期望 13(FixLengths 应仍生效,不被 ComputeChecksums 开关影响)", udp.Length)
	}
}

// TestUDPChecksumAuto 未写 → 自动计算非零(IPv4 下 UDP checksum 非零为合规默认)。
func TestUDPChecksumAuto(t *testing.T) {
	s := udpChecksumScenario(nil)
	pkts := readPackets(t, buildScenarioPcap(t, s))
	udp := pkts[0].Layer(layers.LayerTypeUDP).(*layers.UDP)
	if udp.Checksum == 0 {
		t.Fatalf("udp checksum=0,期望自动计算非零")
	}
}
