package builder

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/gopacket/gopacket/layers"

	"github.com/Epicccal/pMaker/internal/scenario"
)

func ipProtoFor(next string) layers.IPProtocol {
	switch next {
	case "tcp":
		return layers.IPProtocolTCP
	case "udp":
		return layers.IPProtocolUDP
	case "icmp":
		return layers.IPProtocolICMPv4
	case "icmpv6", "icmp6":
		return layers.IPProtocolICMPv6
	case "gre":
		return layers.IPProtocolGRE
	case "ipv4":
		return layers.IPProtocolIPv4 // IP-in-IP
	case "ipv6":
		return layers.IPProtocolIPv6 // IPv6-in-IPv6
	default:
		return layers.IPProtocolTCP
	}
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
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    src.To4(),
		DstIP:    dst.To4(),
		Protocol: ipProtoFor(next),
	}
	if f.TTL != nil {
		ip.TTL = *f.TTL
	}
	if f.Protocol != nil {
		ip.Protocol = ipProtoFor(*f.Protocol)
	}
	if f.FixLengths != nil || f.Checksum != nil {
		slog.Warn("最小版忽略 ipv4 畸形开关(fix_lengths/checksum),序列化为合规包", "src", f.Src, "dst", f.Dst)
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
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      src.To16(),
		DstIP:      dst.To16(),
		NextHeader: ipProtoFor(next),
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
		ip.NextHeader = ipProtoFor(*f.NextHeader)
	}
	return ip, nil
}

// buildGRE:GRE.Protocol 为其载荷的 EtherType。
func buildGRE(next string) *layers.GRE {
	return &layers.GRE{Protocol: ethTypeFor(next)}
}
