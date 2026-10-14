package flow_test

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/flow"
	"github.com/Epicccal/pMaker/internal/scenario"
)

// 本文件覆盖 TCP flow 中 dns 层的展开(DNS over TCP,RFC 1035 §4.2.2):
//   - 每个 dns 层独立带 2 字节长度前缀,多个 dns 拼接 = 段内流水线
//   - segment.mss 切的是「前缀 + 消息」字节流,前缀只在首段(mss: 1 可把前缀切开)
//   - seq 推进量含前缀
//   - VXLAN 隧道内 TCP 会话同样加前缀(outer UDP 不误判)
// 端到端(pcap + 手剥前缀回读)见 internal/golden/dns_tcp_test.go。

func dnsLayer(id uint16) scenario.Layer {
	return scenario.Layer{Type: "dns", Fields: &scenario.DNSFields{
		ID:        id,
		Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "A"}},
	}}
}

// dnsTCPBytes 是 dns 层在 TCP 承载下的期望字节:2 字节长度 + UDP 形态消息。
func dnsTCPBytes(t *testing.T, l scenario.Layer) []byte {
	t.Helper()
	msg, err := builder.PayloadBytes(l)
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	return append([]byte{byte(len(msg) >> 8), byte(len(msg))}, msg...)
}

// chunkOf 取展开包末尾 payload_hex(数据段字节);纯控制包返回 nil。
func chunkOf(t *testing.T, p scenario.Packet) []byte {
	t.Helper()
	last := p.Stack[len(p.Stack)-1]
	h, ok := last.Fields.(scenario.PayloadHex)
	if !ok {
		return nil
	}
	b, err := scenario.ParsePayloadHex(string(h))
	if err != nil {
		t.Fatalf("payload_hex: %v", err)
	}
	return b
}

func TestFlowDNSOverTCP(t *testing.T) {
	f := scenario.FlowSpec{
		Name: "dot",
		Stack: []scenario.Layer{
			{Type: "eth", Fields: &scenario.EthFields{Src: "00:00:00:00:00:01", Dst: "00:00:00:00:00:02"}},
			{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.53"}},
			{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 53, ClientISN: 1000, ServerISN: 5000}},
			{Type: "tcp_session", Fields: &scenario.TCPSessionFields{Open: "none", Close: "none"}},
		},
		Messages: []scenario.Message{
			{From: "src", Stack: []scenario.Layer{dnsLayer(1), dnsLayer(2)}},
			{From: "src", Segment: &scenario.Segment{MSS: 1}, Stack: []scenario.Layer{dnsLayer(3)}},
		},
	}
	pkts, _, _, err := flow.Expand(f, time.Time{}, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}

	pipelined := append(dnsTCPBytes(t, dnsLayer(1)), dnsTCPBytes(t, dnsLayer(2))...)
	if got := chunkOf(t, pkts[0].Packet); !bytes.Equal(got, pipelined) {
		t.Fatalf("流水线段:\n got  %s\n want %s", hex.EncodeToString(got), hex.EncodeToString(pipelined))
	}

	// pkts[1] 是对端 ACK;其后是 mss=1 切出的逐字节数据段 + 末尾对端 ACK。
	var joined []byte
	var segs int
	for _, p := range pkts[2:] {
		if tcpOf(p.Packet).SPort != 49152 {
			continue
		}
		c := chunkOf(t, p.Packet)
		if segs == 0 {
			if seq := tcpOf(p.Packet).Seq; seq == nil || *seq != 1000+uint32(len(pipelined)) {
				t.Fatalf("第二条消息首段 seq = %v,期望 %d(推进量含前缀)", seq, 1000+len(pipelined))
			}
		}
		joined = append(joined, c...)
		segs++
	}
	want := dnsTCPBytes(t, dnsLayer(3))
	if !bytes.Equal(joined, want) || segs != len(want) {
		t.Fatalf("切段重组(%d 段):\n got  %s\n want %s", segs, hex.EncodeToString(joined), hex.EncodeToString(want))
	}
}

func TestFlowVXLANInnerDNSOverTCP(t *testing.T) {
	f := scenario.FlowSpec{Name: "vx", Stack: vxlanFlowStack()}
	f.Messages = []scenario.Message{{From: "src", Stack: []scenario.Layer{dnsLayer(7)}}}
	pkts, _, _, err := flow.Expand(f, time.Time{}, nil)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if got, want := chunkOf(t, pkts[0].Packet), dnsTCPBytes(t, dnsLayer(7)); !bytes.Equal(got, want) {
		t.Fatalf("VXLAN 内层 TCP 的 dns 应带前缀:\n got  %s\n want %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}
