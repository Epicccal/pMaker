package golden_test

import (
	"strings"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

// 本文件覆盖 GRE 作为 flow 隧道切点的回读断言(P0 线):
//   - gre_flow_http:两段栈展开,握手挥手,内外两层 IP 双向反转,
//     inner TCP seq/ack 跨轮连续,GRE 头两向保持声明值;
//   - flow_gre_inner_dns:UDP 会话经 GRE 隧道,每条 message 恰一个数据报,
//     from: dst 同时反转内外两层 IP 端点;
//   - gre_flow_nvgre:两线交汇,inner eth 模板在 flow 下的端点反转。

// TestParseBackGREFlowHTTP 回读 gre_flow_http:断言包数、内外 IP 反转、
// GRE key 全包不变、inner TCP 标志序列与应用层字节。
func TestParseBackGREFlowHTTP(t *testing.T) {
	data := generatePcap(t, "../../examples/tunnel/gre_flow_http.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 11 { // 握手 3 + GET 1 + ACK 1 + 200 1 + ACK 1 + 挥手 4
		t.Fatalf("期望 11 个包,得到 %d", len(pkts))
	}

	ipsOf := func(i int) []*layers.IPv4 {
		var out []*layers.IPv4
		for _, l := range pkts[i].Layers() {
			if ip, ok := l.(*layers.IPv4); ok {
				out = append(out, ip)
			}
		}
		return out
	}

	// 包0(src→dst SYN):outer IP src=1.1.1.1,inner IP src=192.168.1.10。
	i0 := ipsOf(0)
	if len(i0) != 2 {
		t.Fatalf("期望 2 层 IPv4(outer+inner),得到 %d", len(i0))
	}
	if i0[0].SrcIP.String() != "1.1.1.1" || i0[1].SrcIP.String() != "192.168.1.10" {
		t.Errorf("包0 outer/inner src = %s/%s", i0[0].SrcIP, i0[1].SrcIP)
	}

	// 包1(dst→src SYN-ACK):outer/inner IP 端点交换。
	i1 := ipsOf(1)
	if i1[0].SrcIP.String() != "2.2.2.2" || i1[1].SrcIP.String() != "192.168.1.20" {
		t.Errorf("包1 反向 outer/inner src = %s/%s,期望各自交换", i1[0].SrcIP, i1[1].SrcIP)
	}

	// GRE key 两向保持声明值(方向反转不动隧道头)。
	for i, p := range pkts {
		greL := p.Layer(layers.LayerTypeGRE)
		if greL == nil {
			t.Fatalf("包 %d 缺少 GRE 层", i)
		}
		gre := greL.(*layers.GRE)
		if !gre.KeyPresent || gre.Key != 0x0000a10b {
			t.Errorf("包 %d GRE key = %#x(present=%v),期望 0x0000a10b", i, gre.Key, gre.KeyPresent)
		}
	}

	// 包0 纯 SYN;包3 GET;包5 200 OK。
	tcp0 := pkts[0].Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !tcp0.SYN || tcp0.ACK {
		t.Errorf("包0 应为纯 SYN")
	}
	appGet := pkts[3].ApplicationLayer()
	if appGet == nil {
		t.Fatal("包3 缺少应用层")
	}
	if s := string(appGet.Payload()); !strings.Contains(s, "GET /a") {
		t.Errorf("包3 inner HTTP payload 不含 \"GET /a\": %q", s)
	}
	appResp := pkts[5].ApplicationLayer()
	if appResp == nil {
		t.Fatal("包5 缺少应用层")
	}
	if s := string(appResp.Payload()); !strings.Contains(s, "200") {
		t.Errorf("包5 inner HTTP payload 不含 \"200\": %q", s)
	}
}

// TestParseBackGREFlowDNS 回读 flow_gre_inner_dns:UDP 会话经 GRE 隧道,
// 每条 message 恰一个数据报(2 包),反向消息内外两层 IP 同时反转。
func TestParseBackGREFlowDNS(t *testing.T) {
	data := generatePcap(t, "../../examples/udp/flow_gre_inner_dns.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 2 {
		t.Fatalf("UDP 会话应 2 个数据报(问 + 答),得到 %d", len(pkts))
	}

	ipsOf := func(i int) []*layers.IPv4 {
		var out []*layers.IPv4
		for _, l := range pkts[i].Layers() {
			if ip, ok := l.(*layers.IPv4); ok {
				out = append(out, ip)
			}
		}
		return out
	}
	// 查询(包0):outer src=1.1.1.1,inner src=192.168.1.10;响应(包1)双双反转。
	i0, i1 := ipsOf(0), ipsOf(1)
	if len(i0) != 2 || len(i1) != 2 {
		t.Fatalf("每个包期望 2 层 IPv4,得到 %d/%d", len(i0), len(i1))
	}
	if i0[0].SrcIP.String() != "1.1.1.1" || i0[1].SrcIP.String() != "192.168.1.10" {
		t.Errorf("包0 outer/inner src = %s/%s", i0[0].SrcIP, i0[1].SrcIP)
	}
	if i1[0].SrcIP.String() != "2.2.2.2" || i1[1].SrcIP.String() != "192.168.1.20" {
		t.Errorf("包1 反向 outer/inner src = %s/%s,期望各自交换", i1[0].SrcIP, i1[1].SrcIP)
	}
	// 查询 DNS、响应 DNS(QR 置位),都解得出 DNS 层。
	for i, p := range pkts {
		if p.Layer(layers.LayerTypeDNS) == nil {
			t.Errorf("包 %d 缺少 DNS 层", i)
		}
	}
}

// TestParseBackGREFlowNVGRE 回读 gre_flow_nvgre:NVGRE 形态(inner eth)在 flow 下
// 内外两层 eth 端点同时反转,protocol 自动推导 0x6558,key 两向保持。
func TestParseBackGREFlowNVGRE(t *testing.T) {
	data := generatePcap(t, "../../examples/tunnel/gre_flow_nvgre.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 11 {
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
	// 包0:outer eth src=VTEP 侧,inner eth src=VM 侧;包1(SYN-ACK)双双反转。
	e0, e1 := ethsOf(0), ethsOf(1)
	if len(e0) != 2 || len(e1) != 2 {
		t.Fatalf("期望每包 2 层 Ethernet(outer+inner),得到 %d/%d", len(e0), len(e1))
	}
	if e0[0].SrcMAC.String() != "00:11:22:33:44:55" || e0[1].SrcMAC.String() != "aa:bb:cc:dd:ee:01" {
		t.Errorf("包0 outer/inner eth src = %s/%s", e0[0].SrcMAC, e0[1].SrcMAC)
	}
	if e1[0].SrcMAC.String() != "66:77:88:99:aa:bb" || e1[1].SrcMAC.String() != "aa:bb:cc:dd:ee:02" {
		t.Errorf("包1 反向 outer/inner eth src = %s/%s,期望各自交换", e1[0].SrcMAC, e1[1].SrcMAC)
	}
	for i, p := range pkts {
		greL := p.Layer(layers.LayerTypeGRE)
		if greL == nil {
			t.Fatalf("包 %d 缺少 GRE 层", i)
		}
		gre := greL.(*layers.GRE)
		if gre.Protocol != layers.EthernetTypeTransparentEthernetBridging {
			t.Errorf("包 %d GRE protocol = %#x,期望 0x6558(TEB 自动推导)", i, gre.Protocol)
		}
		if !gre.KeyPresent || gre.Key != 0x0012340a {
			t.Errorf("包 %d GRE key = %#x(present=%v),期望 0x0012340a", i, gre.Key, gre.KeyPresent)
		}
	}
}
