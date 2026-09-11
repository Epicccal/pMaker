package golden_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

// 本文件覆盖 VXLAN 端到端:examples/tunnel/vxlan_*.yaml 的 golden 逐字节比对由
// TestExamplesGolden 自动收录(新增示例即自动要求生成对应 golden)。
// 此处补 gopacket 逐层解回读:外层 eth/IP/UDP/VXLAN/inner eth 串接、VNI 落值、
// inner VLAN/IPv4/TCP 与内外层 checksum 绑定。

// TestParseBackVXLANIPv4 回读 vxlan_ipv4:4789 端口下逐层解,
// 断言 VXLAN VNI、inner Ethernet/IP/TCP 串接。
func TestParseBackVXLANIPv4(t *testing.T) {
	data := generatePcap(t, "../../examples/tunnel/vxlan_ipv4.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 1 {
		t.Fatalf("期望 1 个包,得到 %d", len(pkts))
	}
	pkt := pkts[0]

	vxlanL := pkt.Layer(layers.LayerTypeVXLAN)
	if vxlanL == nil {
		t.Fatalf("缺少 VXLAN 层(回读断链)")
	}
	vx := vxlanL.(*layers.VXLAN)
	if vx.VNI != 100 {
		t.Errorf("VXLAN VNI = %d,期望 100", vx.VNI)
	}
	if !vx.ValidIDFlag {
		t.Errorf("VXLAN ValidIDFlag = false,期望 true(缺省规范头)")
	}

	// 外层 IPv4 一层 + 内层 IPv4 一层。
	if got := countLayers(pkt, layers.LayerTypeIPv4); got != 2 {
		t.Errorf("期望 2 层 IPv4(外层+内层),得到 %d", got)
	}
	outerIP := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !outerIP.SrcIP.Equal(net.ParseIP("10.0.0.10")) {
		t.Errorf("外层 IPv4 src = %s,期望 10.0.0.10", outerIP.SrcIP)
	}

	innerEthL := pkt.Layer(layers.LayerTypeEthernet)
	if innerEthL == nil {
		t.Fatalf("缺少 inner Ethernet 层")
	}
	// Ethernet 层 2 个(gopacket 把外层 eth 也作为一个 layer;LinkLayer + inner)。
	if got := countLayers(pkt, layers.LayerTypeEthernet); got != 2 {
		t.Errorf("期望 2 层 Ethernet(外层 link 层+inner),得到 %d", got)
	}

	tcpL := pkt.Layer(layers.LayerTypeTCP)
	if tcpL == nil {
		t.Fatalf("缺少内层 TCP 层")
	}
	if tcp := tcpL.(*layers.TCP); tcp.SrcPort != 40000 || tcp.DstPort != 80 {
		t.Errorf("内层 TCP 端口 = %d/%d,期望 40000/80", tcp.SrcPort, tcp.DstPort)
	}
}

// TestParseBackVXLANIPv6 回读 vxlan_ipv6:外层 IPv6/UDP → VXLAN → 内层 IPv6/TCP。
func TestParseBackVXLANIPv6(t *testing.T) {
	data := generatePcap(t, "../../examples/tunnel/vxlan_ipv6.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 1 {
		t.Fatalf("期望 1 个包,得到 %d", len(pkts))
	}
	pkt := pkts[0]

	vx := pkt.Layer(layers.LayerTypeVXLAN)
	if vx == nil {
		t.Fatalf("缺少 VXLAN 层")
	}
	if vx.(*layers.VXLAN).VNI != 200 {
		t.Errorf("VXLAN VNI = %d,期望 200", vx.(*layers.VXLAN).VNI)
	}
	if got := countLayers(pkt, layers.LayerTypeIPv6); got != 2 {
		t.Errorf("期望 2 层 IPv6(外层+内层),得到 %d", got)
	}
	tcpL := pkt.Layer(layers.LayerTypeTCP)
	if tcpL == nil {
		t.Fatalf("缺少内层 TCP 层")
	}
	if tcp := tcpL.(*layers.TCP); tcp.DstPort != 443 {
		t.Errorf("内层 TCP dport = %d,期望 443", tcp.DstPort)
	}
}

// TestParseBackVXLANVLAN 回读 vxlan_vlan:inner Ethernet → Dot1Q → IPv4 → UDP。
func TestParseBackVXLANVLAN(t *testing.T) {
	data := generatePcap(t, "../../examples/tunnel/vxlan_vlan.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 1 {
		t.Fatalf("期望 1 个包,得到 %d", len(pkts))
	}
	pkt := pkts[0]

	if pkt.Layer(layers.LayerTypeVXLAN) == nil {
		t.Fatalf("缺少 VXLAN 层")
	}
	dot1qL := pkt.Layer(layers.LayerTypeDot1Q)
	if dot1qL == nil {
		t.Fatalf("缺少 inner Dot1Q 层(inner EtherType 0x8100 串接失败)")
	}
	if vid := dot1qL.(*layers.Dot1Q).VLANIdentifier; vid != 500 {
		t.Errorf("inner VID = %d,期望 500", vid)
	}
	udpL := pkt.Layer(layers.LayerTypeUDP)
	if udpL == nil {
		t.Fatalf("缺少 UDP 层")
	}
	// Layer() 返回第一个 UDP(外层 49154→4789);内层 UDP 用 Layers() 找最后一个。
	var innerUDP *layers.UDP
	for _, l := range pkt.Layers() {
		if u, ok := l.(*layers.UDP); ok {
			innerUDP = u
		}
	}
	if innerUDP == nil {
		t.Fatalf("缺少内层 UDP 层")
	}
	if innerUDP.SrcPort != 5353 || innerUDP.DstPort != 53 {
		t.Errorf("内层 UDP 端口 = %d/%d,期望 5353/53", innerUDP.SrcPort, innerUDP.DstPort)
	}
	if innerUDP.Checksum == 0 {
		t.Errorf("内层 UDP checksum=0,期望已用内层 IPv4 伪首部计算")
	}
}

// TestParseBackVXLANEdge 回读 vxlan_edge:VNI 边界值与 valid_id_flag=false 的
// wire 落值(dport 均为 4789,可逐层解)。
func TestParseBackVXLANEdge(t *testing.T) {
	data := generatePcap(t, "../../examples/tunnel/vxlan_edge.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 3 {
		t.Fatalf("期望 3 个包,得到 %d", len(pkts))
	}

	vnis := []uint32{100, 0, 0xFFFFFF}
	for i, want := range vnis {
		vxL := pkts[i].Layer(layers.LayerTypeVXLAN)
		if vxL == nil {
			t.Fatalf("包 %d 缺少 VXLAN 层", i+1)
		}
		vx := vxL.(*layers.VXLAN)
		if vx.VNI != want {
			t.Errorf("包 %d VNI = %d,期望 %d", i+1, vx.VNI, want)
		}
	}
	// 包① valid_id_flag: false → 'I' 位落 0。
	if vx := pkts[0].Layer(layers.LayerTypeVXLAN).(*layers.VXLAN); vx.ValidIDFlag {
		t.Errorf("包① ValidIDFlag = true,期望 false")
	}
	// 包②③ 缺省 true。
	for _, i := range []int{1, 2} {
		if vx := pkts[i].Layer(layers.LayerTypeVXLAN).(*layers.VXLAN); !vx.ValidIDFlag {
			t.Errorf("包%d ValidIDFlag = false,期望 true(缺省)", i+1)
		}
	}
	// 包① payload_hex 0xdeadbeef 原样落帧内(inner IPv4 之后;帧最小长度的
	// 0 padding 在其之后,属 gopacket/writer 的以太最小帧行为)。
	raw := pkts[0].Data()
	const payloadOff = 50 + 14 + 20 // inner eth + inner ipv4 头之后
	if !bytes.Equal(raw[payloadOff:payloadOff+4], []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("包① payload 字节 = %x,期望 deadbeef", raw[payloadOff:payloadOff+4])
	}
}

// TestParseBackVXLANZeroCsum 回读 vxlan_zero_csum:outer IPv4 + UDP checksum 显式 0
// (RFC 7348 §5),断言 wire 上 outer UDP checksum 字段落 0(覆盖值原样落值,未被自动计算覆盖)。
func TestParseBackVXLANZeroCsum(t *testing.T) {
	data := generatePcap(t, "../../examples/tunnel/vxlan_zero_csum.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 1 {
		t.Fatalf("期望 1 个包,得到 %d", len(pkts))
	}
	udpL := pkts[0].Layer(layers.LayerTypeUDP)
	if udpL == nil {
		t.Fatalf("缺少 outer UDP 层(回读断链)")
	}
	udp := udpL.(*layers.UDP)
	if udp.DstPort != 4789 {
		t.Errorf("outer UDP dport = %d,期望 4789", udp.DstPort)
	}
	if udp.Checksum != 0 {
		t.Errorf("outer UDP checksum = 0x%04x,期望 0x0000(RFC 7348 §5 显式传 0)", udp.Checksum)
	}
}
