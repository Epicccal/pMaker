package golden_test

import (
	"bytes"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// TestTelnetNegotiationContent 回读 negotiation.yaml,断言 TCP payload 逐字节含
// IAC WILL ECHO / IAC WILL SGA / IAC DO SGA / IAC DONT ECHO(多层拼接后连续)。
func TestTelnetNegotiationContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/telnet/negotiation.yaml")
	// IAC=0xFF WILL=0xFB DO=0xFD DONT=0xFE;ECHO=1 SGA=3
	want := []byte{0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03, 0xff, 0xfd, 0x03, 0xff, 0xfe, 0x01}
	if !bytes.Contains(pcap, want) {
		t.Errorf("pcap 不含连续协商序列 %x", want)
	}
}

// TestTelnetTTypeNAWSContent 回读 ttype_naws.yaml,断言 SB TTYPE IS xterm-256color
// 与 SB NAWS 80x24 的大端字节。
func TestTelnetTTypeNAWSContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/telnet/ttype_naws.yaml")
	// TTYPE IS: IAC SB 24 00 "xterm-256color" IAC SE
	ttype := append([]byte{0xff, 0xfa, 0x18, 0x00}, []byte("xterm-256color")...)
	ttype = append(ttype, 0xff, 0xf0)
	if !bytes.Contains(pcap, ttype) {
		t.Errorf("pcap 不含 SB TTYPE IS xterm-256color")
	}
	// NAWS 80x24: IAC SB 31 00 50 00 18 IAC SE
	naws := []byte{0xff, 0xfa, 0x1f, 0x00, 0x50, 0x00, 0x18, 0xff, 0xf0}
	if !bytes.Contains(pcap, naws) {
		t.Errorf("pcap 不含 SB NAWS 80x24 大端字节")
	}
}

// TestTelnetTextEscapeContent 验证 IAC 转义:text 含字面 0xFF 时输出 IAC IAC。
func TestTelnetTextEscapeContent(t *testing.T) {
	// 构造含 0xFF 的 NVT 文本 standalone packet。
	s := &scenario.Scenario{
		LinkType: "ethernet",
		Packets: []scenario.Packet{{
			Stack: []scenario.Layer{
				{Type: "eth", Fields: &scenario.EthFields{Src: "00:11:22:33:44:55", Dst: "66:77:88:99:aa:bb"}},
				{Type: "ipv4", Fields: &scenario.IPv4Fields{Src: "10.0.0.1", Dst: "10.0.0.2"}},
				{Type: "tcp", Fields: &scenario.TCPFields{SPort: 1234, DPort: 23}},
				{Type: "telnet", Fields: &scenario.TelnetFields{Args: "\xff\xffhi"}},
			},
		}},
	}
	pcap := generatePcapScenario(t, s)
	// 两个 0xFF 各转义为 IAC IAC:ff ff ff ff h i
	want := []byte{0xff, 0xff, 0xff, 0xff, 'h', 'i'}
	if !bytes.Contains(pcap, want) {
		t.Errorf("pcap 不含 IAC IAC 转义序列 %x", want)
	}
}

// TestTelnetLoginSessionContent 回读 flow pcap,断言协商 + login:/Password: +
// TTYPE IS + 用户输入在合流 pcap 中按序出现,且握手/挥手标志序列正确。
func TestTelnetLoginSessionContent(t *testing.T) {
	pcap := generatePcap(t, "../../examples/telnet/login_session.yaml")
	// 协商
	for _, want := range [][]byte{
		{0xff, 0xfb, 0x01}, // IAC WILL ECHO
		{0xff, 0xfb, 0x03}, // IAC WILL SGA
		{0xff, 0xfd, 0x03}, // IAC DO SGA
		{0xff, 0xfd, 0x01}, // IAC DO ECHO
		// TTYPE SEND: IAC SB 24 01 IAC SE
		{0xff, 0xfa, 0x18, 0x01, 0xff, 0xf0},
		// TTYPE IS xterm-256color
		append(append([]byte{0xff, 0xfa, 0x18, 0x00}, []byte("xterm-256color")...), []byte{0xff, 0xf0}...),
	} {
		if !bytes.Contains(pcap, want) {
			t.Errorf("pcap 不含协商/subneg 序列 %x", want)
		}
	}
	// NVT 文本
	for _, want := range []string{"login: ", "root\r\n", "Password: ", "secret\r\n", "Welcome to pMaker.\r\n"} {
		if !bytes.Contains(pcap, []byte(want)) {
			t.Errorf("pcap 不含 NVT 文本 %q", want)
		}
	}

	// 握手/挥手标志序列:SYN → SYN,ACK → ACK …(handshake)→ 末尾 FIN,ACK 四次挥手。
	r, err := pcapgo.NewReader(bytes.NewReader(pcap))
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	var flags []string
	for {
		raw, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(raw, r.LinkType(), gopacket.Default)
		if tcpL := p.Layer(layers.LayerTypeTCP); tcpL != nil {
			tcp := tcpL.(*layers.TCP)
			flags = append(flags, tcpFlagString(tcp))
		}
	}
	if len(flags) < 3 {
		t.Fatalf("期望至少 3 个 TCP 包(握手),得到 %d", len(flags))
	}
	if flags[0] != "SYN" || flags[1] != "SYN,ACK" || flags[2] != "ACK" {
		t.Errorf("握手标志序列错误: %v", flags[:3])
	}
	// 挥手:末四个包应为 FIN,ACK / ACK / FIN,ACK / ACK。
	if len(flags) < 7 {
		t.Fatalf("包数不足以包含挥手: %d", len(flags))
	}
	tail := flags[len(flags)-4:]
	if tail[0] != "FIN,ACK" || tail[1] != "ACK" || tail[2] != "FIN,ACK" || tail[3] != "ACK" {
		t.Errorf("挥手标志序列错误: %v", tail)
	}
}
