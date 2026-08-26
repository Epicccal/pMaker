package golden_test

import (
	"bytes"
	"flag"
	"fmt"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

var update = flag.Bool("update", false, "regenerate golden pcap files")

// generatePcap 跑完整链路 scenario.Load → Validate → plan.Plan →
// builder.BuildPlanned → writer.WriteTo,返回 pcap 字节。
func generatePcap(t *testing.T, path string) []byte {
	t.Helper()
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate %s: %v", path, err)
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("plan %s: %v", path, err)
	}
	pkts, err := builder.BuildPlanned(planned)
	if err != nil {
		t.Fatalf("build %s: %v", path, err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return buf.Bytes()
}

// generatePcapScenario 对已构造的 Scenario 跑完整链路返回 pcap 字节。
func generatePcapScenario(t *testing.T, s *scenario.Scenario) []byte {
	t.Helper()
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	planned, err := plan.Plan(s)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	pkts, err := builder.BuildPlanned(planned)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write: %v", err)
	}
	return buf.Bytes()
}

// readPackets 用 pcapgo 回读所有包。
func readPackets(t *testing.T, data []byte) []gopacket.Packet {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
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

// readICMPPackets 回读所有带 ICMPv4 层的包。
func readICMPPackets(t *testing.T, data []byte) []*layers.ICMPv4 {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	var out []*layers.ICMPv4
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		if l := p.Layer(layers.LayerTypeICMPv4); l != nil {
			out = append(out, l.(*layers.ICMPv4))
		}
	}
	return out
}

// readDNSPackets 回读所有带 DNS 层的包。
func readDNSPackets(t *testing.T, data []byte) []*layers.DNS {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	var out []*layers.DNS
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		if l := p.Layer(layers.LayerTypeDNS); l != nil {
			out = append(out, l.(*layers.DNS))
		}
	}
	return out
}

// tcpFlagString 把 TCP 标志位拼成可读串(顺序 SYN/FIN/ACK/RST,惯用表示)。
func tcpFlagString(tcp *layers.TCP) string {
	var parts []string
	if tcp.SYN {
		parts = append(parts, "SYN")
	}
	if tcp.FIN {
		parts = append(parts, "FIN")
	}
	if tcp.ACK {
		parts = append(parts, "ACK")
	}
	if tcp.RST {
		parts = append(parts, "RST")
	}
	return strings.Join(parts, ",")
}

// brotliBytesForTest 返回与 builder 完全一致的 br 压缩字节,供 round-trip 复用。
func brotliBytesForTest(t *testing.T, src []byte) []byte {
	t.Helper()
	b, err := brotliBytes(src)
	if err != nil {
		t.Fatalf("br: %v", err)
	}
	return b
}

// brotliBytes 用与 builder.applyContentCodings 一致的 brotli 参数
// (brotli.BestSpeed、确定性)压缩字节。
func brotliBytes(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	bw := brotli.NewWriterLevel(&buf, brotli.BestSpeed)
	if _, err := bw.Write(src); err != nil {
		return nil, fmt.Errorf("br write: %w", err)
	}
	if err := bw.Close(); err != nil {
		return nil, fmt.Errorf("br close: %w", err)
	}
	return buf.Bytes(), nil
}
