package builder

import (
	"encoding/binary"
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
// 错误类(typ<128)按 RFC 4443 §3 在 Checksum 与 quote 之间插入 4 字节类型相关
// 字段(reserved):Type1/3=Unused(0)、Type2=MTU、Type4=Pointer,由调用方作为
// 独立 Payload 层置于 icmp 之后。
func buildICMPv6(ctx buildContext, f *scenario.ICMPv6Fields) (*layers.ICMPv6, *layers.ICMPv6Echo, []byte, []byte, error) {
	typ, err := icmpv6Type(f.Type)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	code, err := icmpv6Code(f.Code)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	payload, err := icmpv6Payload(ctx, f)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(typ, code)}

	// 类型相关字段合法性:mtu 仅 packet_too_big、pointer 仅 parameter_problem。
	// echo 与其它错误类型一律不得设置。
	if f.MTU != nil && typ != 2 {
		return nil, nil, nil, nil, fmt.Errorf("mtu 仅 packet_too_big(type 2)可用,当前 type=%d", typ)
	}
	if f.Pointer != nil && typ != 4 {
		return nil, nil, nil, nil, fmt.Errorf("pointer 仅 parameter_problem(type 4)可用,当前 type=%d", typ)
	}

	var echo *layers.ICMPv6Echo
	var reserved []byte
	if typ == 128 || typ == 129 { // echo_request / echo_reply
		echo = &layers.ICMPv6Echo{}
		if f.ID != nil {
			if *f.ID > 0xffff {
				return nil, nil, nil, nil, fmt.Errorf("id 超出 uint16: %d", *f.ID)
			}
			echo.Identifier = uint16(*f.ID)
		}
		echo.SeqNumber = f.Seq
	} else {
		if f.ID != nil || f.Seq != 0 {
			return nil, nil, nil, nil, fmt.Errorf("id/seq 仅支持 echo_request/echo_reply")
		}
		// 错误报文:构造 4 字节类型相关字段(RFC 4443 §3)。
		reserved = make([]byte, 4)
		switch typ {
		case 2: // packet_too_big
			if f.MTU != nil {
				binary.BigEndian.PutUint32(reserved, *f.MTU)
			}
		case 4: // parameter_problem
			if f.Pointer != nil {
				binary.BigEndian.PutUint32(reserved, *f.Pointer)
			}
		}
	}
	if f.Checksum != nil {
		slog.Warn("最小版忽略 icmpv6 checksum 覆盖")
	}
	return icmp, echo, reserved, payload, nil
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

// icmpv6QuoteFrom 按 RFC 4443 §2.4(c) 从触发包提取 quote:错误消息须尽量包含
// 整个触发包,仅受"整个错误包不超过最小 IPv6 MTU(1280 字节)"限制。外层 IPv6
// 头(40)+ ICMPv6 头(4)+ 类型相关 4 字节字段共 48 字节开销,故 quote 上限 1232
// 字节。当前 IPv6 层不带扩展头,从 IPv6 固定头起整段截取。(区别于 ICMPv4 RFC 792
// 的"头+8 字节"。)
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
	const maxQuote = 1280 - 40 - 8 // 1232;最小 IPv6 MTU 减去外层 IPv6 头、ICMPv6 头与类型相关 4 字节开销
	quoteLen := len(b)
	if quoteLen > maxQuote {
		quoteLen = maxQuote
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
