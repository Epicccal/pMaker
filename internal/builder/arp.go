package builder

import (
	"fmt"
	"net"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

var zeroMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}

// buildARP 构造 ARP 层。hardware_length/protocol_length 覆盖时地址字段随之补齐
// (补零)或截断 —— gopacket 的 ARP.SerializeTo 在 FixLengths 下用 len(地址切片)
// 反写 length 字段,不联动就只是把那两个字节改回 6/4,畸形用例落不到 wire。
func buildARP(f *scenario.ARPLayer) (*layers.ARP, error) {
	hwLen, protoLen := 6, 4
	if f.HardwareLength != nil {
		hwLen = int(*f.HardwareLength)
	}
	if f.ProtocolLength != nil {
		protoLen = int(*f.ProtocolLength)
	}

	arp := &layers.ARP{
		AddrType:        layers.LinkTypeEthernet,
		Protocol:        layers.EthernetTypeIPv4,
		HwAddressSize:   uint8(hwLen),
		ProtAddressSize: uint8(protoLen),
		Operation:       *f.Operation,
	}

	// hardware_type: 直接落 uint16,不走 LinkType 映射
	// (ARP hardware type 与 pcap LinkType 数值并非通用等价)
	if f.HardwareType != nil {
		arp.AddrType = layers.LinkType(*f.HardwareType)
	}
	if f.ProtocolType != nil {
		arp.Protocol = layers.EthernetType(*f.ProtocolType)
	}

	var err error
	arp.SourceHwAddress, err = arpMAC(f.SenderHWAddr, hwLen, "sender_hw_addr")
	if err != nil {
		return nil, err
	}
	arp.DstHwAddress, err = arpMAC(f.TargetHWAddr, hwLen, "target_hw_addr")
	if err != nil {
		return nil, err
	}
	arp.SourceProtAddress, err = arpIPv4(f.SenderProtoAddr, protoLen, "sender_proto_addr")
	if err != nil {
		return nil, err
	}
	arp.DstProtAddress, err = arpIPv4(f.TargetProtoAddr, protoLen, "target_proto_addr")
	if err != nil {
		return nil, err
	}
	return arp, nil
}

// arpMAC 解析 MAC(空值按全零),再补齐或截断到 hwLen 字节。
func arpMAC(s string, hwLen int, field string) ([]byte, error) {
	var hw net.HardwareAddr
	if s != "" {
		var err error
		hw, err = net.ParseMAC(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
	} else {
		hw = zeroMAC
	}
	return fitAddr(hw, hwLen), nil
}

// arpIPv4 解析 IPv4(空值按 0.0.0.0),再补齐或截断到 protoLen 字节。
func arpIPv4(s string, protoLen int, field string) ([]byte, error) {
	var ip net.IP
	if s != "" {
		ip = net.ParseIP(s).To4()
		if ip == nil {
			return nil, fmt.Errorf("%s: %q 不是有效 IPv4", field, s)
		}
	} else {
		ip = net.IP{0, 0, 0, 0}
	}
	return fitAddr(ip, protoLen), nil
}

// fitAddr 把地址字节补齐(补零)或截断到 n 字节。
func fitAddr(addr []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, addr)
	return out
}
