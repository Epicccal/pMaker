package builder

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

func buildTCP(f *scenario.TCPFields) (*layers.TCP, error) {
	t := &layers.TCP{
		SrcPort: layers.TCPPort(f.SPort),
		DstPort: layers.TCPPort(f.DPort),
		Window:  65535,
	}
	if f.Seq != nil {
		t.Seq = *f.Seq
	}
	if f.Ack != nil {
		t.Ack = *f.Ack
	}
	for _, fl := range f.Flags {
		switch strings.ToUpper(fl) {
		case "SYN":
			t.SYN = true
		case "ACK":
			t.ACK = true
		case "PSH":
			t.PSH = true
		case "FIN":
			t.FIN = true
		case "RST":
			t.RST = true
		case "URG":
			t.URG = true
		default:
			return nil, fmt.Errorf("未知 TCP flag %q", fl)
		}
	}
	if f.Checksum != nil {
		slog.Warn("最小版忽略 tcp checksum 覆盖", "sport", f.SPort, "dport", f.DPort)
	}
	if f.MSS != nil {
		t.Options = append(t.Options, layers.TCPOption{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{byte(*f.MSS >> 8), byte(*f.MSS)},
		})
	}
	return t, nil
}

func buildUDP(f *scenario.UDPFields) *layers.UDP {
	return &layers.UDP{SrcPort: layers.UDPPort(f.SPort), DstPort: layers.UDPPort(f.DPort)}
}
