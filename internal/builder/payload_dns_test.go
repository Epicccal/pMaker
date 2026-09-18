package builder_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/builder"
	"github.com/Epicccal/pMaker/internal/scenario"
	"github.com/Epicccal/pMaker/internal/writer"
)

// 本文件覆盖 PayloadBytes 的 dns 分支(payload.go):UDP flow 的 message.stack 产
// DNS 消息字节的通道。单层序列化(buildDNS 返回的 layers.DNS 或 dnsRawLayer 经
// SerializeTo)须与 standalone eth/ipv4/udp/dns 包里的 wire DNS payload 逐字节一致
// —— flow 展开的数据报与手写包不能有两种字节形态。
//
// 端到端(DNS 问答 flow → pcap → 回读)见 internal/golden 的 UDP flow golden 测试。

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
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.10", Dst: "10.0.0.53", TTL: u8ptr(64)}},
				{Type: "udp", Fields: &scenario.UDPFields{SPort: 53000, DPort: 53}},
				{Type: "dns", Fields: f},
			},
		}},
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
		udp := p.Layer(layers.LayerTypeUDP).(*layers.UDP)
		return udp.LayerPayload()
	}
	t.Fatal("未读到 UDP 层")
	return nil
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
