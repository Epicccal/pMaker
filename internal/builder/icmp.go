package builder

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/scenario"
)

func buildICMP(ctx buildContext, f *scenario.ICMPFields) (*layers.ICMPv4, []byte, error) {
	typ, err := icmpType(f.Type)
	if err != nil {
		return nil, nil, err
	}
	code, err := icmpCode(f.Code)
	if err != nil {
		return nil, nil, err
	}
	payload, err := icmpPayload(ctx, f)
	if err != nil {
		return nil, nil, err
	}

	// 类型相关字段合法性(RFC 792):
	// - gateway 仅 redirect(type 5)
	// - pointer 仅 parameter_problem(type 12)
	// - mtu 仅 destination_unreachable(type 3) code 4(RFC 1191)
	if f.Gateway != nil && typ != 5 {
		return nil, nil, fmt.Errorf("gateway 仅 redirect(type 5)可用,当前 type=%d", typ)
	}
	if f.Pointer != nil && typ != 12 {
		return nil, nil, fmt.Errorf("pointer 仅 parameter_problem(type 12)可用,当前 type=%d", typ)
	}
	if f.MTU != nil && !(typ == 3 && code == 4) {
		return nil, nil, fmt.Errorf("mtu 仅 destination_unreachable(type 3) code 4 可用,当前 type=%d code=%d", typ, code)
	}

	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(typ, code)}
	if typ == 0 || typ == 8 {
		if f.ID != nil {
			if *f.ID > 0xffff {
				return nil, nil, fmt.Errorf("id 超出 uint16: %d", *f.ID)
			}
			icmp.Id = uint16(*f.ID)
		}
		icmp.Seq = f.Seq
	} else {
		if f.ID != nil || f.Seq != 0 {
			return nil, nil, fmt.Errorf("id/seq 仅支持 echo_request/echo_reply")
		}
		// 非 echo:把类型相关字段映射到 ICMPv4 头 bytes 4-7(gopacket 的 Id/Seq)。
		switch typ {
		case 5: // redirect:Gateway IPv4 → bytes 4-7
			if f.Gateway != nil {
				ip := net.ParseIP(*f.Gateway).To4()
				if ip == nil {
					return nil, nil, fmt.Errorf("gateway %q 不是合法 IPv4", *f.Gateway)
				}
				icmp.Id = binary.BigEndian.Uint16(ip[0:2])
				icmp.Seq = binary.BigEndian.Uint16(ip[2:4])
			}
		case 12: // parameter_problem:Pointer → byte 4(Id 高字节)
			if f.Pointer != nil {
				icmp.Id = uint16(*f.Pointer) << 8
			}
		case 3: // destination_unreachable code 4:MTU → bytes 6-7(Seq)
			if f.MTU != nil {
				icmp.Seq = *f.MTU
			}
		}
	}
	if f.Checksum != nil {
		slog.Warn("最小版忽略 icmp checksum 覆盖")
	}
	return icmp, payload, nil
}

func icmpPayload(ctx buildContext, f *scenario.ICMPFields) ([]byte, error) {
	if f.QuoteFrom != "" {
		return icmpQuoteFrom(ctx, f.QuoteFrom)
	}
	if f.Quote != nil {
		return serializeStack(ctx, f.Quote.Stack)
	}
	if f.PayloadHex != "" {
		return scenario.ParsePayloadHex(f.PayloadHex)
	}
	return []byte(f.Payload), nil
}

// icmpQuoteFrom 按 RFC 792 从触发包提取 quote:internet 头(IPv4 头,IHL×4 字节)
// + 原始数据报数据的前 64 位(8 字节)。从序列化后的 IPv4 stack 回解析 IHL 以
// 兼容带选项的头;触发包短于头+8 时截到可用长度。(区别于 ICMPv6 RFC 4443 的
// "尽量包含整个触发包,上限 1280 字节"。)
func icmpQuoteFrom(ctx buildContext, name string) ([]byte, error) {
	p, ok := ctx.packetsByName[name]
	if !ok {
		return nil, fmt.Errorf("quote_from 引用未知 packet %q", name)
	}
	stack, err := ipv4Stack(p)
	if err != nil {
		return nil, fmt.Errorf("quote_from %q: %w", name, err)
	}
	b, err := serializeStack(ctx, stack)
	if err != nil {
		return nil, err
	}
	pkt := gopacket.NewPacket(b, layers.LayerTypeIPv4, gopacket.Default)
	l := pkt.Layer(layers.LayerTypeIPv4)
	if l == nil {
		return nil, fmt.Errorf("未解析出 IPv4 quote")
	}
	ip := l.(*layers.IPv4)
	headerLen := int(ip.IHL) * 4
	if headerLen == 0 {
		headerLen = 20
	}
	if len(b) < headerLen {
		return nil, fmt.Errorf("IPv4 quote 长度不足: %d < %d", len(b), headerLen)
	}
	quoteLen := headerLen + 8
	if quoteLen > len(b) {
		quoteLen = len(b)
	}
	return append([]byte(nil), b[:quoteLen]...), nil
}

func ipv4Stack(p scenario.Packet) ([]scenario.Layer, error) {
	for i, l := range p.Stack {
		if l.Type == "ipv4" {
			return p.Stack[i:], nil
		}
	}
	return nil, fmt.Errorf("被引用 packet 缺少 ipv4 层")
}

func icmpType(node yaml.Node) (uint8, error) {
	return parseICMPByte(node, map[string]uint8{
		"echo_reply":              0,
		"destination_unreachable": 3,
		"redirect":                5,
		"echo_request":            8,
		"time_exceeded":           11,
		"parameter_problem":       12,
	}, 8, "type")
}

func icmpCode(node yaml.Node) (uint8, error) {
	return parseICMPByte(node, map[string]uint8{
		"net_unreachable":                     0,
		"host_unreachable":                    1,
		"protocol_unreachable":                2,
		"port_unreachable":                    3,
		"fragmentation_needed":                4,
		"source_route_failed":                 5,
		"ttl_exceeded":                        0,
		"fragment_reassembly_time_exceeded":   1,
		"fragment_reassembly_time_exceeded_0": 1, // 容错:避免拼写提示时额外处理
	}, 0, "code")
}

func parseICMPByte(node yaml.Node, names map[string]uint8, def uint8, field string) (uint8, error) {
	if node.Kind == 0 || node.Value == "" {
		return def, nil
	}
	var n uint64
	if err := node.Decode(&n); err == nil {
		if n > 0xff {
			return 0, fmt.Errorf("icmp %s 超出 uint8: %d", field, n)
		}
		return uint8(n), nil
	}
	var s string
	if err := node.Decode(&s); err != nil {
		return 0, fmt.Errorf("icmp %s 需要名字或数字: %w", field, err)
	}
	key := strings.ToLower(strings.TrimSpace(s))
	if v, ok := names[key]; ok {
		return v, nil
	}
	parsed, err := strconv.ParseUint(key, 0, 8)
	if err != nil {
		return 0, fmt.Errorf("未知 icmp %s %q", field, s)
	}
	return uint8(parsed), nil
}
