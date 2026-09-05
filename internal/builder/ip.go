package builder

import (
	"fmt"
	"net"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// lookupIPProto 推导表:层名 → IP 协议号。空/payload/payload_hex(兜底与末层)落 TCP 惯例缺省。
// 查不到返回 false,由调用方按语境(自动推导 vs 显式覆盖)出对应文案的报错 —— 两条路径改法不同。
func lookupIPProto(next string) (layers.IPProtocol, bool) {
	switch next {
	case "tcp":
		return layers.IPProtocolTCP, true
	case "udp":
		return layers.IPProtocolUDP, true
	case "icmp":
		return layers.IPProtocolICMPv4, true
	case "icmpv6", "icmp6":
		return layers.IPProtocolICMPv6, true
	case "gre":
		return layers.IPProtocolGRE, true
	case "ipv4":
		return layers.IPProtocolIPv4, true // IP-in-IP
	case "ipv6":
		return layers.IPProtocolIPv6, true // IPv6-in-IPv6
	case "", "payload", "payload_hex":
		return layers.IPProtocolTCP, true
	default:
		return 0, false
	}
}

// ipProtoFor 自动推导路径。历史行为是查不到静默落 6(TCP),悄悄断链;现报错。
// 故意断链仍走 protocol/next_header 显式覆盖。
func ipProtoFor(next string) (layers.IPProtocol, error) {
	p, ok := lookupIPProto(next)
	if !ok {
		return 0, fmt.Errorf("无法从下一层 %q 推导 IP 协议号:只可推导 tcp/udp/icmp/icmpv6/gre/ipv4/ipv6(兜底层 payload/payload_hex 与末层缺省 TCP);要制造断链请显式写 protocol/next_header(只认枚举名),不支持的后接内容走 payload_hex 整段手拼", next)
	}
	return p, nil
}

// ipProtoOverride 显式覆盖路径(protocol/next_header)。用户已写覆盖字段,
// 报错不能再指引「请显式写」(循环指引)。
func ipProtoOverride(field, value string) (layers.IPProtocol, error) {
	p, ok := lookupIPProto(value)
	if !ok {
		return 0, fmt.Errorf("%s 覆盖值 %q 不是合法协议名:只认 tcp/udp/icmp/icmpv6(icmp6)/gre/ipv4/ipv6,不认数字或其它名字(如 sctp/47);任意协议号当前不支持,走 payload_hex 整段手拼", field, value)
	}
	return p, nil
}

func buildIPv4(f *scenario.IPv4Fields, next string) (*layers.IPv4, error) {
	src := net.ParseIP(f.Src)
	dst := net.ParseIP(f.Dst)
	if src == nil || src.To4() == nil {
		return nil, fmt.Errorf("src ip %q 不是合法 IPv4", f.Src)
	}
	if dst == nil || dst.To4() == nil {
		return nil, fmt.Errorf("dst ip %q 不是合法 IPv4", f.Dst)
	}
	proto, err := ipProtoFor(next)
	if err != nil {
		return nil, err
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    src.To4(),
		DstIP:    dst.To4(),
		Protocol: proto,
	}
	if f.TTL != nil {
		ip.TTL = *f.TTL
	}
	if f.Protocol != nil {
		ip.Protocol, err = ipProtoOverride("protocol", *f.Protocol)
		if err != nil {
			return nil, err
		}
	}
	if f.Checksum != nil {
		ip.Checksum = uint16(*f.Checksum)
	}
	return ip, nil
}

func buildIPv6(f *scenario.IPv6Fields, next string) (*layers.IPv6, error) {
	src := net.ParseIP(f.Src)
	dst := net.ParseIP(f.Dst)
	if src == nil || src.To4() != nil {
		return nil, fmt.Errorf("src ip %q 不是合法 IPv6", f.Src)
	}
	if dst == nil || dst.To4() != nil {
		return nil, fmt.Errorf("dst ip %q 不是合法 IPv6", f.Dst)
	}
	proto, err := ipProtoFor(next)
	if err != nil {
		return nil, err
	}
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      src.To16(),
		DstIP:      dst.To16(),
		NextHeader: proto,
	}
	if f.HopLimit != nil {
		ip.HopLimit = *f.HopLimit
	}
	if f.TrafficClass != nil {
		ip.TrafficClass = *f.TrafficClass
	}
	if f.FlowLabel != nil {
		ip.FlowLabel = *f.FlowLabel
	}
	if f.NextHeader != nil {
		ip.NextHeader, err = ipProtoOverride("next_header", *f.NextHeader)
		if err != nil {
			return nil, err
		}
	}
	return ip, nil
}

// buildGRE:GRE.Protocol 为其载荷的 EtherType。
func buildGRE(next string) (*layers.GRE, error) {
	et, err := ethTypeFor(next)
	if err != nil {
		return nil, err
	}
	return &layers.GRE{Protocol: et}, nil
}
