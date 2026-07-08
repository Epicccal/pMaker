package builder_test

import (
	"bytes"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

// genPcap 跑完整链路 scenario -> builder -> writer,返回 pcap 字节。
func genPcap(t *testing.T, path string) ([]byte, string) {
	t.Helper()
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pkts, err := builder.Build(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write: %v", err)
	}
	return buf.Bytes(), s.LinkType
}

// readPackets 用 pcapgo 回读所有包。
func readPackets(t *testing.T, data []byte) []gopacket.Packet {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcapgo reader: %v", err)
	}
	var pkts []gopacket.Packet
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		pkts = append(pkts, gopacket.NewPacket(raw, r.LinkType(), gopacket.Default))
	}
	return pkts
}

func countLayers(pkt gopacket.Packet, lt gopacket.LayerType) int {
	n := 0
	for _, l := range pkt.Layers() {
		if l.LayerType() == lt {
			n++
		}
	}
	return n
}

// TestParseBackHTTP 回读 http_stack,断言 Ethernet/IPv4/TCP 与 HTTP 请求行。
func TestParseBackHTTP(t *testing.T) {
	data, _ := genPcap(t, "../../examples/http_stack.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 1 {
		t.Fatalf("期望 1 个包,得到 %d", len(pkts))
	}
	p := pkts[0]
	for _, lt := range []gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeIPv4, layers.LayerTypeTCP} {
		if p.Layer(lt) == nil {
			t.Errorf("缺少 %v 层", lt)
		}
	}
	app := p.ApplicationLayer()
	if app == nil || !bytes.Contains(app.Payload(), []byte("GET /index.html HTTP/1.1")) {
		t.Errorf("payload 不含预期的 HTTP 请求行")
	}
	if app != nil && !bytes.Contains(app.Payload(), []byte("Host: example.com")) {
		t.Errorf("payload 不含 Host 头")
	}
}

// TestParseBackQinQGRE 回读 qinq_gre,验证封装链正确解码(证明 next-proto 串接)。
func TestParseBackQinQGRE(t *testing.T) {
	data, _ := genPcap(t, "../../examples/qinq_gre.yaml")
	pkts := readPackets(t, data)
	if len(pkts) != 3 {
		t.Fatalf("期望 3 个包,得到 %d", len(pkts))
	}

	// 包①:QinQ 双层 VLAN,内层能解到 IPv4 + TCP
	if got := countLayers(pkts[0], layers.LayerTypeDot1Q); got != 2 {
		t.Errorf("包①期望 2 层 Dot1Q(QinQ),得到 %d", got)
	}
	if pkts[0].Layer(layers.LayerTypeIPv4) == nil || pkts[0].Layer(layers.LayerTypeTCP) == nil {
		t.Errorf("包①内层未解到 IPv4/TCP")
	}

	// 包②:GRE 隧道,含内层 IPv4
	if pkts[1].Layer(layers.LayerTypeGRE) == nil {
		t.Errorf("包②缺少 GRE 层")
	}
	if got := countLayers(pkts[1], layers.LayerTypeIPv4); got != 2 {
		t.Errorf("包②期望 2 层 IPv4(外层+隧道内层),得到 %d", got)
	}
}
