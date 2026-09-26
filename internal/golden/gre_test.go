package golden_test

import (
	"testing"

	"github.com/gopacket/gopacket/layers"
)

// 本文件覆盖 GRE checksum(C=1)与内层 mtu 分片交互的 golden 断言(设计 §13.3):
//   - checksum_present: true + mtu:各片载荷不同,逐片 checksum 各不相同才是正确行为
//     (RFC 2784 §2.1 的覆盖范围 = GRE 头 + 本帧实际载荷);gopacket 回读逐片
//     VerifyChecksum 通过(下方有断言);不断言各片相等。
//   - checksum: 0xdead + mtu:该路径 ComputeChecksums=false,各片同为 0xdead ——
//     覆盖值不被分片重序列化改回,若自动算的值泄漏进下一片,某片会出现非 0xdead。

// TestGREChecksumFragGolden:逐片 checksum 各自正确(分片路径上 ComputeChecksums
// 逐片重算,不泄漏、不复用)。
func TestGREChecksumFragGolden(t *testing.T) {
	data := generatePcap(t, "../../examples/ip_fragment/gre_checksum_frag.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 2 {
		t.Fatalf("应 2 片,得到 %d", len(pkts))
	}
	for k, p := range pkts {
		greL := p.Layer(layers.LayerTypeGRE)
		if greL == nil {
			t.Fatalf("片 %d 未解析出 GRE 层", k)
		}
		gre := greL.(*layers.GRE)
		if !gre.ChecksumPresent {
			t.Fatalf("片 %d: C=0,期望 C=1 且 checksum 自动算", k)
		}
		if gre.Checksum == 0 {
			t.Errorf("片 %d: Checksum=0,应逐片自动计算", k)
		}
		// RFC 2784 §2.1 覆盖范围 = GRE 头 + 本片实际载荷;逐片各自算对(回读验证)
		if _, v := gre.VerifyChecksum(); !v.Valid {
			t.Errorf("片 %d: checksum 回读验证失败: actual=%#x correct=%#x", k, v.Actual, v.Correct)
		}
	}
	// 独立断言:各片 checksum 不必相等(载荷不同,正确行为是各自算对)。
	first := pkts[0].Layer(layers.LayerTypeGRE).(*layers.GRE).Checksum
	second := pkts[1].Layer(layers.LayerTypeGRE).(*layers.GRE).Checksum
	if first == second {
		t.Errorf("两片载荷不同,checksum 却同为 0x%04x(自动算逻辑可能未逐片重算)", first)
	}
}

// TestGREChecksumBadFragGolden:覆盖值路径各片同为 0xdead(ComputeChecksums 已关,
// 分片重序列化不会把覆盖值改回自动算的值)。
func TestGREChecksumBadFragGolden(t *testing.T) {
	data := generatePcap(t, "../../examples/ip_fragment/gre_checksum_bad_frag.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 2 {
		t.Fatalf("应 2 片,得到 %d", len(pkts))
	}
	var want uint16 = 0xdead
	for k, p := range pkts {
		greL := p.Layer(layers.LayerTypeGRE)
		if greL == nil {
			t.Fatalf("片 %d 缺少 GRE 层", k)
		}
		gre := greL.(*layers.GRE)
		if !gre.ChecksumPresent {
			t.Errorf("片 %d: C=0,应隐含 C=1(写 checksum 即置位)", k)
		}
		if gre.Checksum != want {
			t.Errorf("片 %d: Checksum=%#x,应保持覆盖值 0xdead", k, gre.Checksum)
		}
	}
}
