package builder_test

import (
	"testing"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 ipv4 checksum 三态覆盖:写了 → 回读等于指定值;没写 → 自动计算非零且正确。

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
