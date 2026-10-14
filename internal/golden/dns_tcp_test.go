package golden_test

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// 本文件回读 examples/dns/tcp_*.yaml(DNS over TCP)。
//
// 例外说明:gopacket 拿不到 TCP 上的 DNS 层 —— 默认 DecodeOptions 下 TCP 之后一律落
// Payload;开 DecodeStreamsAsDatagrams 则按裸消息解 DNS,撞上 2 字节长度前缀即
// DecodeFailure。故此处 eth/ip/tcp 交 gopacket 解析,TCP payload 按方向重组后手剥前缀,
// 再调 layers.DNS.DecodeFromBytes。

// tcpStreams 按方向拼接 TCP payload(包序即 seq 序,flow 展开无乱序/重传)。
func tcpStreams(t *testing.T, data []byte, clientPort layers.TCPPort) (client, server []byte) {
	t.Helper()
	for _, p := range readPackets(t, data) {
		tcp := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if tcp.SrcPort == clientPort {
			client = append(client, tcp.Payload...)
		} else {
			server = append(server, tcp.Payload...)
		}
	}
	return client, server
}

// decodeTCPDNSStream 按 RFC 1035 §4.2.2 逐条切出「2 字节长度 + 消息」并解码;
// 前缀与剩余字节不符即失败(前缀诚实性)。
func decodeTCPDNSStream(t *testing.T, stream []byte) []*layers.DNS {
	t.Helper()
	var out []*layers.DNS
	for len(stream) > 0 {
		if len(stream) < 2 {
			t.Fatalf("残留 %d 字节,不足 2 字节长度前缀", len(stream))
		}
		n := int(binary.BigEndian.Uint16(stream))
		if len(stream)-2 < n {
			t.Fatalf("前缀声明 %d 字节,剩余仅 %d", n, len(stream)-2)
		}
		d := &layers.DNS{}
		if err := d.DecodeFromBytes(stream[2:2+n], gopacket.NilDecodeFeedback); err != nil {
			t.Fatalf("DNS 解码: %v", err)
		}
		out = append(out, d)
		stream = stream[2+n:]
	}
	return out
}

// TestParseBackDNSTCPKeepalive:同一连接两轮问答,第二轮响应 mss=16 切段;
// 两方向重组后各切出 2 条 DNS 消息,字段与声明一致。
func TestParseBackDNSTCPKeepalive(t *testing.T) {
	client, server := tcpStreams(t, generatePcap(t, "../../examples/dns/tcp_keepalive.yaml"), 49152)

	qs := decodeTCPDNSStream(t, client)
	rs := decodeTCPDNSStream(t, server)
	if len(qs) != 2 || len(rs) != 2 {
		t.Fatalf("期望 2 问 2 答,得到 %d 问 %d 答", len(qs), len(rs))
	}
	for i, want := range []struct {
		id  uint16
		typ layers.DNSType
		ip  string
	}{
		{0x1234, layers.DNSTypeA, "93.184.216.34"},
		{0x1235, layers.DNSTypeAAAA, "2606:2800:220:1:248:1893:25c8:1946"},
	} {
		q, r := qs[i], rs[i]
		if q.ID != want.id || q.QR || len(q.Questions) != 1 || q.Questions[0].Type != want.typ {
			t.Errorf("第 %d 问: id=%#x qr=%v questions=%v", i, q.ID, q.QR, q.Questions)
		}
		if r.ID != want.id || !r.QR || len(r.Answers) != 1 || !r.Answers[0].IP.Equal(net.ParseIP(want.ip)) {
			t.Errorf("第 %d 答: id=%#x qr=%v answers=%v", i, r.ID, r.QR, r.Answers)
		}
	}
}

// TestParseBackDNSTCPMissingPrefix:payload_hex 原样落裸消息,不被自动加前缀 ——
// 首 2 字节即 DNS id 0x1234,当作长度远超实际字节。
func TestParseBackDNSTCPMissingPrefix(t *testing.T) {
	client, server := tcpStreams(t, generatePcap(t, "../../examples/dns/tcp_missing_prefix.yaml"), 49152)
	if len(server) != 0 {
		t.Fatalf("服务端不应有数据,得到 %d 字节", len(server))
	}
	if len(client) != 29 || binary.BigEndian.Uint16(client) != 0x1234 {
		t.Fatalf("期望 29 字节裸 DNS 消息且首 2 字节为 id 0x1234,得到 %x", client)
	}
	d := &layers.DNS{}
	if err := d.DecodeFromBytes(client, gopacket.NilDecodeFeedback); err != nil || d.ID != 0x1234 {
		t.Fatalf("裸字节本身应是合法 DNS 消息: id=%#x err=%v", d.ID, err)
	}
}
