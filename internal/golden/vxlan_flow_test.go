package golden_test

import (
	"strings"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

// TestParseBackVXLANFlow 回读 vxlan_flow_http:flow 展开的隧道会话,
// 断言 outer/inner Ethernet 方向反转、VNI 全包不变、inner TCP 标志序列、
// inner HTTP payload 字节(GET /a 与 200 OK)。
func TestParseBackVXLANFlow(t *testing.T) {
	data := generatePcap(t, "../../examples/tunnel/vxlan_flow_http.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 11 { // 握手 3 + GET 1 + ACK 1 + 200 1 + ACK 1 + 挥手 4
		t.Fatalf("期望 11 个包,得到 %d", len(pkts))
	}

	ethsOf := func(i int) []*layers.Ethernet {
		var out []*layers.Ethernet
		for _, l := range pkts[i].Layers() {
			if e, ok := l.(*layers.Ethernet); ok {
				out = append(out, e)
			}
		}
		return out
	}

	// 包0(src→dst SYN):outer eth src=VTEP-A,inner eth src=VM-A。
	e0 := ethsOf(0)
	if len(e0) != 2 {
		t.Fatalf("期望 2 层 Ethernet,得到 %d", len(e0))
	}
	if e0[0].SrcMAC.String() != "00:11:22:33:44:55" || e0[1].SrcMAC.String() != "00:22:33:44:55:66" {
		t.Errorf("包0 outer/inner eth src = %s/%s", e0[0].SrcMAC, e0[1].SrcMAC)
	}

	// 包1(dst→src SYN-ACK):outer/inner 端点交换。
	e1 := ethsOf(1)
	if e1[0].SrcMAC.String() != "66:77:88:99:aa:bb" || e1[1].SrcMAC.String() != "00:33:44:55:66:77" {
		t.Errorf("包1 反向 outer/inner eth src = %s/%s,期望各自交换", e1[0].SrcMAC, e1[1].SrcMAC)
	}

	// VNI 全包 100。
	for i, p := range pkts {
		vxL := p.Layer(layers.LayerTypeVXLAN)
		if vxL == nil {
			t.Fatalf("包 %d 缺少 VXLAN 层", i)
		}
		if vx := vxL.(*layers.VXLAN); vx.VNI != 100 {
			t.Errorf("包 %d VNI = %d", i, vx.VNI)
		}
	}

	// 包0 SYN;outer UDP dport 两向 4789。
	tcp0 := pkts[0].Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !tcp0.SYN || tcp0.ACK {
		t.Errorf("包0 应为纯 SYN")
	}
	for i, p := range pkts {
		if u, ok := p.Layer(layers.LayerTypeUDP).(*layers.UDP); ok && u.DstPort != 4789 {
			t.Errorf("包 %d outer UDP dport = %d,期望 4789", i, u.DstPort)
		}
	}

	// 包3(src→dst GET):inner TCP payload 含 "GET /a"。
	appGet := pkts[3].ApplicationLayer()
	if appGet == nil {
		t.Fatal("包3 缺少应用层")
	}
	if s := string(appGet.Payload()); !strings.Contains(s, "GET /a") {
		t.Errorf("包3 inner HTTP payload 不含 \"GET /a\",得到 %q", s)
	}

	// 包5(dst→src 200 OK):inner TCP payload 含 "200"。
	appResp := pkts[5].ApplicationLayer()
	if appResp == nil {
		t.Fatal("包5 缺少应用层")
	}
	if s := string(appResp.Payload()); !strings.Contains(s, "200") {
		t.Errorf("包5 inner HTTP payload 不含 \"200\",得到 %q", s)
	}
}

// TestParseBackVXLANFlowZeroCsum 回读 vxlan_flow_zero_csum:展开后每包 outer UDP
// checksum 字段均为 0(覆盖值原样透传)。
func TestParseBackVXLANFlowZeroCsum(t *testing.T) {
	data := generatePcap(t, "../../examples/tunnel/vxlan_flow_zero_csum.yaml")
	pkts := readPackets(t, data)
	for i, p := range pkts {
		u, ok := p.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok {
			t.Fatalf("包 %d 缺少 outer UDP 层", i)
		}
		if u.Checksum != 0 {
			t.Errorf("包 %d outer UDP checksum = 0x%04x,期望 0x0000", i, u.Checksum)
		}
	}
}
