package builder_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

// 本文件覆盖 PayloadBytes / PayloadBytesIn 的 dns 分支(payload.go):flow 的 message.stack 产
// DNS 消息字节的通道。单层序列化(buildDNS 返回的 layers.DNS 或 dnsRawLayer 经
// SerializeTo)须与 standalone 包里的 wire payload 逐字节一致(UDP 裸消息、TCP 带
// 2 字节长度前缀)—— flow 展开的包与手写包不能有两种字节形态。
//
// 端到端见 internal/golden 的 UDP flow 与 DNS over TCP golden 测试。

// dnsQueryFields 是最小 A 查询(gopacket 编码路径)。
func dnsQueryFields() *scenario.DNSFields {
	return &scenario.DNSFields{
		ID: 0x1234,
		Questions: []scenario.DNSQuestionFields{
			{Name: "example.com", Type: "A"},
		},
	}
}

// TestPayloadBytesDNSMatchesWire:gopacket 与手写两条编码路径,单层 PayloadBytes 的
// 输出都等于 standalone 包序列化后 UDP 层的 payload(截去 8 字节 UDP 头)。
func TestPayloadBytesDNSMatchesWire(t *testing.T) {
	for name, f := range map[string]*scenario.DNSFields{
		"gopacket 编码路径": dnsQueryFields(),
		"手写编码路径(payload_hex)": {
			ID:        0x4321,
			Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "A"}},
			Answers: []scenario.DNSRRFields{
				{Name: "example.com", Type: "99", TTL: 300, PayloadHex: "0xdeadbeef"},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := builder.PayloadBytes(scenario.Layer{Type: "dns", Fields: f})
			if err != nil {
				t.Fatalf("PayloadBytes: %v", err)
			}
			want := standaloneDNSPayload(t, f)
			if !bytes.Equal(got, want) {
				t.Fatalf("单层序列化与 wire payload 不一致:\n got  %s\n want %s",
					hex.EncodeToString(got), hex.EncodeToString(want))
			}
		})
	}
}

// standaloneDNSPayload 序列化一个 eth/ipv4/udp/dns standalone 包,取 UDP payload
// (DNS 消息字节)。
func standaloneDNSPayload(t *testing.T, f *scenario.DNSFields) []byte {
	t.Helper()
	return standaloneL4Payload(t,
		scenario.Layer{Type: "udp", Fields: &scenario.UDPFields{SPort: 53000, DPort: 53}},
		scenario.Layer{Type: "dns", Fields: f})
}

// standaloneL4Payload 序列化 eth/ipv4 + inner 的 standalone 包,取传输层 payload。
func standaloneL4Payload(t *testing.T, inner ...scenario.Layer) []byte {
	t.Helper()
	stack := []scenario.Layer{
		{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
		{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.53", TTL: u8ptr(64)}},
	}
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets:  []scenario.Packet{{Stack: append(stack, inner...)}},
	}
	pkts, err := buildPackets(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var buf bytes.Buffer
	if err := writer.WriteTo(&buf, s.LinkType, pkts); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, p := range readPackets(t, buf.Bytes()) {
		if tl := p.TransportLayer(); tl != nil {
			return tl.LayerPayload()
		}
	}
	t.Fatal("未读到传输层")
	return nil
}

// withTCPPrefix 按 RFC 1035 §4.2.2 给 DNS 消息前置 2 字节长度。
func withTCPPrefix(msg []byte) []byte {
	return append([]byte{byte(len(msg) >> 8), byte(len(msg))}, msg...)
}

func tcpLayer() scenario.Layer {
	return scenario.Layer{Type: "tcp", Fields: &scenario.TCPFields{SPort: 49152, DPort: 53, Flags: []string{"PSH", "ACK"}}}
}

// TestPayloadBytesDNSTCPMatchesWire:TCP 承载时两条编码路径都带 2 字节长度前缀,
// PayloadBytesIn(l, true) 与 standalone eth/ipv4/tcp/dns 的 TCP payload 逐字节一致。
func TestPayloadBytesDNSTCPMatchesWire(t *testing.T) {
	for name, f := range map[string]*scenario.DNSFields{
		"gopacket 编码路径": dnsQueryFields(),
		"手写编码路径(payload_hex)": {
			ID:        0x4321,
			Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "A"}},
			Answers: []scenario.DNSRRFields{
				{Name: "example.com", Type: "99", TTL: 300, PayloadHex: "0xdeadbeef"},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			l := scenario.Layer{Type: "dns", Fields: f}
			msg, err := builder.PayloadBytes(l)
			if err != nil {
				t.Fatalf("PayloadBytes: %v", err)
			}
			got, err := builder.PayloadBytesIn(l, true)
			if err != nil {
				t.Fatalf("PayloadBytesIn: %v", err)
			}
			if want := withTCPPrefix(msg); !bytes.Equal(got, want) {
				t.Fatalf("TCP 前缀错误:\n got  %s\n want %s", hex.EncodeToString(got), hex.EncodeToString(want))
			}
			if wire := standaloneL4Payload(t, tcpLayer(), l); !bytes.Equal(got, wire) {
				t.Fatalf("flow 路径与 standalone wire 不一致:\n got  %s\n wire %s", hex.EncodeToString(got), hex.EncodeToString(wire))
			}
		})
	}
}

// TestDNSTCPPrefixNearestTransport:判据是就近传输层而非紧邻前一层 ——
// tcp/payload_hex/dns 中 dns 带前缀、payload_hex 不带。
func TestDNSTCPPrefixNearestTransport(t *testing.T) {
	l := scenario.Layer{Type: "dns", Fields: dnsQueryFields()}
	msg, err := builder.PayloadBytes(l)
	if err != nil {
		t.Fatalf("PayloadBytes: %v", err)
	}
	got := standaloneL4Payload(t, tcpLayer(), scenario.Layer{Type: "payload_hex", Fields: scenario.PayloadHex("0xaabb")}, l)
	want := append([]byte{0xaa, 0xbb}, withTCPPrefix(msg)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("got  %s\nwant %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

// TestDNSTCPPrefixOverflow:消息超 65535 字节无法写 2 字节前缀,硬错而非回绕。
func TestDNSTCPPrefixOverflow(t *testing.T) {
	txt := strings.Repeat("x", 255)
	f := &scenario.DNSFields{}
	for range 260 { // 260 × (13 名 + 10 定长 + 256 RDATA) > 65535
		f.Answers = append(f.Answers, scenario.DNSRRFields{Name: "example.com", Type: "TXT", Data: scalarNode(txt)})
	}
	l := scenario.Layer{Type: "dns", Fields: f}
	if _, err := builder.PayloadBytes(l); err != nil {
		t.Fatalf("UDP 形态不应报错: %v", err)
	}
	_, err := builder.PayloadBytesIn(l, true)
	if err == nil || !strings.Contains(err.Error(), "超过 65535") {
		t.Fatalf("应报前缀溢出,得到 %v", err)
	}
}

// TestPayloadBytesDNSErr:非法 DNS 配置(未知 type 无 payload_hex)经 PayloadBytes
// 报错并带 dns 前缀,而非静默产空字节。空段由 scenario.Validate 在展开前拦截,
// 这里选 build 阶段才暴露的错误。
func TestPayloadBytesDNSErr(t *testing.T) {
	f := &scenario.DNSFields{
		Questions: []scenario.DNSQuestionFields{{Name: "example.com", Type: "A"}},
		Answers: []scenario.DNSRRFields{
			{Name: "example.com", Type: "99", TTL: 300},
		},
	}
	_, err := builder.PayloadBytes(scenario.Layer{Type: "dns", Fields: f})
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("dns")) {
		t.Fatalf("未知 type 无 payload_hex 应报错且带 dns 前缀,得到 %v", err)
	}
}
