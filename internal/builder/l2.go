package builder

import (
	"fmt"
	"net"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// ethTypeFor 按下一层类型推导 EtherType。
func ethTypeFor(next string) layers.EthernetType {
	switch next {
	case "vlan":
		return layers.EthernetTypeDot1Q
	case "ipv4":
		return layers.EthernetTypeIPv4
	case "ipv6":
		return layers.EthernetTypeIPv6
	default:
		return layers.EthernetTypeIPv4
	}
}

func buildEth(f *scenario.EthFields, next string) (*layers.Ethernet, error) {
	src, err := net.ParseMAC(f.Src)
	if err != nil {
		return nil, fmt.Errorf("src mac %q: %w", f.Src, err)
	}
	dst, err := net.ParseMAC(f.Dst)
	if err != nil {
		return nil, fmt.Errorf("dst mac %q: %w", f.Dst, err)
	}
	et := ethTypeFor(next)
	if f.EtherType != nil {
		et = layers.EthernetType(uint16(*f.EtherType))
	}
	return &layers.Ethernet{SrcMAC: src, DstMAC: dst, EthernetType: et}, nil
}

func buildVLAN(f *scenario.VLANFields, next string) *layers.Dot1Q {
	d := &layers.Dot1Q{VLANIdentifier: f.VID}
	switch {
	case f.Type != nil: // 显式覆盖(断链)
		d.Type = layers.EthernetType(uint16(*f.Type))
	case next == "vlan" && f.TPID != nil: // 后一层标签的 TPID
		d.Type = layers.EthernetType(uint16(*f.TPID))
	default:
		d.Type = ethTypeFor(next)
	}
	return d
}
