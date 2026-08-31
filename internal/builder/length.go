package builder

import (
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// lengthOverrideInfo 记录一层哪些长度字段被显式覆盖(两态:非 nil=原样落值,nil=未覆盖、
// 由 fillLengths 按公式补值)。与 serLayers/layerOpts 一一对应、同生命周期。
// ICMPv6 一层 append 出多项时,只有真正的网络/传输层那项非空,其余零值。
type lengthOverrideInfo struct {
	ipv4Length        *scenario.Hex // ipv4 总长度(含头)
	ipv4IHL           *scenario.Hex // ipv4 头部长度(4 位)
	ipv6PayloadLength *scenario.Hex // ipv6 载荷长度(不含 40B 头)
	tcpDataOffset     *scenario.Hex // tcp 数据偏移(4 位)
	udpLength         *scenario.Hex // udp 长度(头 8 + payload)
}

func (i lengthOverrideInfo) any() bool {
	return i.ipv4Length != nil || i.ipv4IHL != nil ||
		i.ipv6PayloadLength != nil || i.tcpDataOffset != nil || i.udpLength != nil
}

// fillLengths 在 SerializeTo 之前补值:此时 buf.Bytes() 是该层 payload(尚未 prepend 本层头),
// 与 gopacket 内部取值时机一致。只对有覆盖(info.any())的层补未覆盖字段为公式值;
// 覆盖字段(含显式 0)原样落值,不碰。无覆盖的层不做事(FixLengths 仍开,gopacket 自动算)。
func fillLengths(l gopacket.SerializableLayer, info lengthOverrideInfo, buf gopacket.SerializeBuffer) error {
	if !info.any() {
		return nil
	}
	switch t := l.(type) {
	case *layers.IPv4:
		optionLen := ipv4OptionSize(t)
		headerLen := 20 + optionLen // gopacket PrependBytes(20+optionLength),实际头字节
		ihl := uint8(5 + optionLen/4)
		if info.ipv4IHL != nil {
			ihl = uint8(*info.ipv4IHL)
		}
		t.IHL = ihl
		if info.ipv4Length != nil {
			t.Length = uint16(*info.ipv4Length)
		} else {
			// gopacket 在 prepend 后取 len(b.Bytes()),含头部;此处 prepend 尚未发生,
			// buf.Bytes() 是 payload,需加上头部长度。
			t.Length = uint16(len(buf.Bytes())) + uint16(headerLen)
		}
	case *layers.IPv6:
		if info.ipv6PayloadLength != nil {
			t.Length = uint16(*info.ipv6PayloadLength)
		} else {
			// gopacket 在 prepend 前取 payload,Length = len(payload);此处 prepend 未发生,
			// buf.Bytes() 即 payload,不含 40B 头。
			t.Length = uint16(len(buf.Bytes()))
		}
	case *layers.TCP:
		optionLen := tcpOptionSize(t)
		padding := 0
		if rem := optionLen % 4; rem != 0 {
			padding = 4 - rem
		}
		dataOffset := uint8((20 + optionLen + padding) / 4)
		if info.tcpDataOffset != nil {
			dataOffset = uint8(*info.tcpDataOffset)
		}
		t.DataOffset = dataOffset
		// padding 也需补:gopacket 在 FixLengths 内会按 option 长度补齐,关掉后需自行处理,
		// 否则 PrependBytes(20+optionLen+padding) 与实际 option 序列化长度不一致。
		if padding > 0 && len(t.Padding) == 0 {
			t.Padding = make([]byte, padding)
		}
	case *layers.UDP:
		if info.udpLength != nil {
			t.Length = uint16(*info.udpLength)
		} else {
			// gopacket 在 prepend 前取 payload,Length = len(payload)+8;此处 prepend 未发生,
			// buf.Bytes() 即 payload。
			t.Length = uint16(len(buf.Bytes())) + 8
		}
	default:
		return fmt.Errorf("层 %s 不支持 length 覆盖", l.LayerType())
	}
	return nil
}

// ipv4OptionSize 返回 IPv4 Options 占用的字节数(与 gopacket IPv4.getIPv4OptionSize 同口径,
// 含 32 位对齐 padding)。IHL = 5 + optionSize/4;pMaker 目前不设 IPv4 Options,恒为 0,
// 按通式写以便后续加 IP option 时不踩。
func ipv4OptionSize(ip *layers.IPv4) int {
	var n int
	for _, opt := range ip.Options {
		switch opt.OptionType {
		case 0, 1:
			n++
		default:
			n += int(opt.OptionLength)
		}
	}
	if n%4 != 0 {
		n += 4 - n%4
	}
	return n
}

// tcpOptionSize 返回 TCP Options 占用的字节数(与 gopacket TCP.SerializeTo 同口径)。
// gopacket 按 option 类型累加:0/1 各 1 字节,其余 2 + len(data)。
func tcpOptionSize(t *layers.TCP) int {
	var n int
	for _, o := range t.Options {
		switch o.OptionType {
		case 0, 1:
			n++
		default:
			n += 2 + len(o.OptionData)
		}
	}
	return n
}
