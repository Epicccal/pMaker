package builder

import (
	"fmt"
	"log/slog"

	"github.com/gopacket/gopacket/layers"
	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// buildICMPv6 构造 ICMPv6 层。
// 与 ICMPv4 不同:校验和依赖 IPv6 伪首部,调用方须在返回后
// icmp.SetNetworkLayerForChecksum(ipv6Layer)(就近内层 IPv6)。
// echo(128/129) 多一层独立的 ICMPv6Echo,序列化时跟在 ICMPv6 之后。
// 非 echo(错误类)只有 ICMPv6 头 + payload(如 quote)。
func buildICMPv6(ctx buildContext, f *scenario.ICMPv6Fields) (*layers.ICMPv6, *layers.ICMPv6Echo, []byte, error) {
	typ, err := icmpv6Type(f.Type)
	if err != nil {
		return nil, nil, nil, err
	}
	code, err := icmpv6Code(f.Code)
	if err != nil {
		return nil, nil, nil, err
	}
	payload, err := icmpv6Payload(ctx, f)
	if err != nil {
		return nil, nil, nil, err
	}

	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(typ, code)}

	var echo *layers.ICMPv6Echo
	if typ == 128 || typ == 129 { // echo_request / echo_reply
		echo = &layers.ICMPv6Echo{}
		if f.ID != nil {
			if *f.ID > 0xffff {
				return nil, nil, nil, fmt.Errorf("id 超出 uint16: %d", *f.ID)
			}
			echo.Identifier = uint16(*f.ID)
		}
		echo.SeqNumber = f.Seq
	} else if f.ID != nil || f.Seq != 0 {
		return nil, nil, nil, fmt.Errorf("id/seq 仅支持 echo_request/echo_reply")
	}
	if f.Checksum != nil {
		slog.Warn("最小版忽略 icmpv6 checksum 覆盖")
	}
	return icmp, echo, payload, nil
}

func icmpv6Payload(ctx buildContext, f *scenario.ICMPv6Fields) ([]byte, error) {
	if f.QuoteFrom != "" {
		return icmpv6QuoteFrom(ctx, f.QuoteFrom)
	}
	if f.Quote != nil {
		return serializeStack(ctx, f.Quote.Stack)
	}
	if f.PayloadHex != "" {
		return scenario.ParsePayloadHex(f.PayloadHex)
	}
	return []byte(f.Payload), nil
}

// icmpv6QuoteFrom 按 RFC 4443 从触发包提取 quote:IPv6 固定头(40 字节,
// 当前 IPv6 层不带扩展头)+ 触发包后续 8 字节。
func icmpv6QuoteFrom(ctx buildContext, name string) ([]byte, error) {
	p, ok := ctx.packetsByName[name]
	if !ok {
		return nil, fmt.Errorf("quote_from 引用未知 packet %q", name)
	}
	stack, err := ipv6Stack(p)
	if err != nil {
		return nil, fmt.Errorf("quote_from %q: %w", name, err)
	}
	b, err := serializeStack(ctx, stack)
	if err != nil {
		return nil, err
	}
	const headerLen = 40 // IPv6 固定头,无 IHL 概念
	if len(b) < headerLen {
		return nil, fmt.Errorf("IPv6 quote 长度不足: %d < %d", len(b), headerLen)
	}
	quoteLen := headerLen + 8
	if quoteLen > len(b) {
		quoteLen = len(b)
	}
	return append([]byte(nil), b[:quoteLen]...), nil
}

func ipv6Stack(p scenario.Packet) ([]scenario.Layer, error) {
	for i, l := range p.Stack {
		if l.Type == "ipv6" {
			return p.Stack[i:], nil
		}
	}
	return nil, fmt.Errorf("被引用 packet 缺少 ipv6 层")
}

func icmpv6Type(node yaml.Node) (uint8, error) {
	return parseICMPByte(node, map[string]uint8{
		"destination_unreachable": 1,
		"packet_too_big":          2,
		"time_exceeded":           3,
		"parameter_problem":       4,
		"echo_request":            128,
		"echo_reply":              129,
	}, 128, "type") // 默认 echo_request(对齐 ICMPv4 默认 8)
}

func icmpv6Code(node yaml.Node) (uint8, error) {
	return parseICMPByte(node, map[string]uint8{
		// destination_unreachable (type 1), RFC 4443
		"no_route":            0,
		"admin_prohibited":    1,
		"beyond_scope":        2,
		"address_unreachable": 3,
		"port_unreachable":    4, // 注意:ICMPv6 中为 4(ICMPv4 为 3)
		"src_policy_failed":   5,
		"reject_route":        6,
		// time_exceeded (type 3)
		"hop_limit_exceeded":                0,
		"fragment_reassembly_time_exceeded": 1,
		// parameter_problem (type 4)
		"erroneous_header_field":   0,
		"unrecognized_next_header": 1,
		"unrecognized_ipv6_option": 2,
	}, 0, "code")
}
