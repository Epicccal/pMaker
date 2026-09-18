package golden_test

import (
	"strings"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

// 本文件回读 examples/udp/ 下三个 UDP 会话 flow 示例:断言「无握手 / 每消息一个数据报 /
// 反向交换端点」的展开语义,与 vxlan_flow_test.go 对 TCP flow 的回读定位一致。

// TestParseBackUDPFlowEcho 回读 flow_echo:UDP 会话最小形态 —— 2 个数据报,无握手无 ACK,
// 反向交换 eth/ip 端点与 udp sport/dport,payload 为声明字节。
func TestParseBackUDPFlowEcho(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/udp/flow_echo.yaml"))
	if len(pkts) != 2 {
		t.Fatalf("期望 2 个数据报(一来一回,无握手),得到 %d", len(pkts))
	}

	for i, want := range []struct{ sport, dport layers.UDPPort }{
		{49152, 7}, // src → dst
		{7, 49152}, // dst → src:声明值交换
	} {
		u := pkts[i].Layer(layers.LayerTypeUDP).(*layers.UDP)
		if u.SrcPort != want.sport || u.DstPort != want.dport {
			t.Errorf("包%d udp %d → %d,期望 %d → %d", i, u.SrcPort, u.DstPort, want.sport, want.dport)
		}
	}

	for i, want := range []string{"ping", "pong"} {
		app := pkts[i].ApplicationLayer()
		if app == nil || string(app.Payload()) != want {
			got := "<nil>"
			if app != nil {
				got = string(app.Payload())
			}
			t.Errorf("包%d payload = %q,期望 %q", i, got, want)
		}
	}
}

// TestParseBackUDPFlowDNS 回读 flow_dns:UDP 会话的头号用例 —— dns 层单层序列化进数据报,
// 问答两向 gopacket 都能解析回 DNS 层,事务 ID 一致,方向由 QR 位区分。
func TestParseBackUDPFlowDNS(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/udp/flow_dns.yaml"))
	if len(pkts) != 2 {
		t.Fatalf("期望 2 个数据报,得到 %d", len(pkts))
	}

	for i, want := range []struct{ sport, dport layers.UDPPort }{
		{40000, 53},
		{53, 40000},
	} {
		u := pkts[i].Layer(layers.LayerTypeUDP).(*layers.UDP)
		if u.SrcPort != want.sport || u.DstPort != want.dport {
			t.Errorf("包%d udp %d → %d,期望 %d → %d", i, u.SrcPort, u.DstPort, want.sport, want.dport)
		}
	}

	q := pkts[0].Layer(layers.LayerTypeDNS).(*layers.DNS)
	if q.ID != 0x1234 || q.QR || q.ResponseCode != layers.DNSResponseCodeNoErr {
		t.Errorf("包0 DNS 应为 id=0x1234 的查询(QR=false),得到 id=0x%04x qr=%v rcode=%v", q.ID, q.QR, q.ResponseCode)
	}
	if len(q.Questions) != 1 || string(q.Questions[0].Name) != "example.com" ||
		q.Questions[0].Type != layers.DNSTypeA {
		t.Errorf("包0 question 与声明不符: %v", q.Questions)
	}

	r := pkts[1].Layer(layers.LayerTypeDNS).(*layers.DNS)
	if r.ID != 0x1234 || !r.QR {
		t.Errorf("包1 DNS 应为 id=0x1234 的响应(QR=true),得到 id=0x%04x qr=%v", r.ID, r.QR)
	}
	if len(r.Answers) != 1 || r.Answers[0].Type != layers.DNSTypeA ||
		r.Answers[0].IP.String() != "93.184.216.34" {
		t.Errorf("包1 answer 与声明不符: %v", r.Answers)
	}
}

// TestParseBackUDPFlowVXLANInnerDNS 回读 flow_vxlan_inner_udp:双 UDP 栈的方向语义 ——
// outer(隧道)UDP 端口与 VNI 两向不变,只有 inner(会话)UDP 端口随方向交换。
func TestParseBackUDPFlowVXLANInnerDNS(t *testing.T) {
	pkts := readPackets(t, generatePcap(t, "../../examples/udp/flow_vxlan_inner_udp.yaml"))
	if len(pkts) != 2 {
		t.Fatalf("期望 2 个数据报,得到 %d", len(pkts))
	}

	for i, p := range pkts {
		if vx := p.Layer(layers.LayerTypeVXLAN).(*layers.VXLAN); vx.VNI != 100 {
			t.Errorf("包%d VNI = %d,期望 100", i, vx.VNI)
		}
		// outer UDP 取第一层(隧道端口 51000 → 4789 两向不变,只有外层 IP 交换)。
		u := p.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if u.SrcPort != 51000 || u.DstPort != 4789 {
			t.Errorf("包%d outer udp %d → %d,期望 51000 → 4789", i, u.SrcPort, u.DstPort)
		}
	}

	// inner UDP 是 VXLAN 之后的第二层:包0 53000 → 53,包1 交换。
	for i, want := range []struct{ sport, dport layers.UDPPort }{
		{53000, 53},
		{53, 53000},
	} {
		var inner *layers.UDP
		for _, l := range pkts[i].Layers() {
			if u, ok := l.(*layers.UDP); ok {
				inner = u // 最后一层 UDP 即 inner(会话)层
			}
		}
		if inner == nil {
			t.Fatalf("包%d 缺少 inner UDP 层", i)
		}
		if inner.SrcPort != want.sport || inner.DstPort != want.dport {
			t.Errorf("包%d inner udp %d → %d,期望 %d → %d", i,
				inner.SrcPort, inner.DstPort, want.sport, want.dport)
		}
	}

	// inner DNS 两向均可解析,事务 ID 一致。
	for i, p := range pkts {
		var dns *layers.DNS
		for _, l := range p.Layers() {
			if d, ok := l.(*layers.DNS); ok {
				dns = d
			}
		}
		if dns == nil || dns.ID != 0x5678 {
			got := "<nil>"
			if dns != nil {
				got = "0x5678 之外的 id"
			}
			t.Errorf("包%d inner DNS 应为 id=0x5678,得到 %s", i, got)
		}
		if dns != nil && !strings.Contains(string(dns.Questions[0].Name), "svc.internal") {
			t.Errorf("包%d inner DNS question = %v", i, dns.Questions)
		}
	}
}
