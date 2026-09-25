package builder_test

import (
	"bytes"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/plan"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

// 本文件收录 builder 测试包共用的辅助函数,避免在各协议测试文件里复制。
// 协议专属的构造助手(如 icmpv4ErrorScenario)随对应测试文件放置。

// genPcap 跑完整链路 scenario -> plan -> builder -> writer,返回 pcap 字节。
func genPcap(t *testing.T, path string) ([]byte, string) {
	t.Helper()
	s, err := scenario.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pkts, err := buildPackets(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write: %v", err)
	}
	return buf.Bytes(), s.LinkType
}

// buildPackets 跑 plan.Plan + builder.BuildPlanned,返回字节包与错误(不 Fatal、不校验)。
func buildPackets(s *scenario.Scenario) ([]builder.OutPacket, error) {
	planned, err := plan.Plan(s)
	if err != nil {
		return nil, err
	}
	return builder.BuildPlanned(planned)
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

// readPcapPackets 用 pcapgo 回读 pcap 字节为 gopacket.Packet 列表。
func readPcapPackets(t *testing.T, data []byte) []gopacket.Packet {
	t.Helper()
	r, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("pcapgo reader: %v", err)
	}
	var out []gopacket.Packet
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		out = append(out, gopacket.NewPacket(raw, r.LinkType(), gopacket.Default))
	}
	return out
}

// buildScenarioPcap 跑 scenario -> plan -> builder -> writer,返回 pcap 字节。
func buildScenarioPcap(t *testing.T, s *scenario.Scenario) []byte {
	t.Helper()
	if err := scenario.Validate(s); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pkts, err := buildPackets(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write: %v", err)
	}
	return buf.Bytes()
}

func u8ptr(v uint8) *uint8 { return &v }

// u32ptr 取 uint32 指针,供可选字段构造。
func u32ptr(v uint32) *uint32 { return &v }
