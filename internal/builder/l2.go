package builder

import (
	"fmt"
	"net"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// ethTypeFor 自动推导路径。查不到时不再沿用历史静默落 0x0800(悄悄断链),报错;
// 故意断链仍走 ethertype/type 显式覆盖,不受影响。
func ethTypeFor(next string) (layers.EthernetType, error) {
	switch next {
	case "vlan":
		return layers.EthernetTypeDot1Q, nil
	case "ipv4":
		return layers.EthernetTypeIPv4, nil
	case "ipv6":
		return layers.EthernetTypeIPv6, nil
	case "", "payload", "payload_hex":
		return layers.EthernetTypeIPv4, nil
	default:
		return 0, fmt.Errorf("无法从下一层 %q 推导 EtherType:只可推导 vlan/ipv4/ipv6(兜底层 payload/payload_hex 与末层缺省 0x0800);非标 TPID/EtherType 请显式写 ethertype/type,不支持的后接内容走 payload_hex 整段手拼", next)
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
	var et layers.EthernetType
	if f.EtherType == nil {
		var err error
		if et, err = ethTypeFor(next); err != nil {
			return nil, err
		}
	} else {
		et = layers.EthernetType(uint16(*f.EtherType))
	}
	return &layers.Ethernet{SrcMAC: src, DstMAC: dst, EthernetType: et}, nil
}

func buildVLAN(f *scenario.VLANFields, next string) (*layers.Dot1Q, error) {
	d := &layers.Dot1Q{VLANIdentifier: f.VID}
	if f.Type != nil { // 显式覆盖(断链)
		d.Type = layers.EthernetType(uint16(*f.Type))
	} else if et, err := ethTypeFor(next); err != nil {
		return nil, err
	} else {
		d.Type = et
	}
	return d, nil
}
