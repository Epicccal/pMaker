package builder

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket/layers"
	"gopkg.in/yaml.v3"

	"github.com/Epicccal/pMaker/internal/scenario"
)

func buildICMP(f *scenario.ICMPFields) (*layers.ICMPv4, []byte, error) {
	typ, err := icmpType(f.Type)
	if err != nil {
		return nil, nil, err
	}
	code, err := icmpCode(f.Code)
	if err != nil {
		return nil, nil, err
	}
	payload, err := icmpPayload(f)
	if err != nil {
		return nil, nil, err
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
	} else if f.ID != nil || f.Seq != 0 {
		return nil, nil, fmt.Errorf("id/seq 仅支持 echo_request/echo_reply")
	}
	if f.Checksum != nil {
		slog.Warn("最小版忽略 icmp checksum 覆盖")
	}
	return icmp, payload, nil
}

func icmpPayload(f *scenario.ICMPFields) ([]byte, error) {
	if f.Quote != nil {
		return serializeStack(f.Quote.Stack)
	}
	if f.PayloadHex != "" {
		return scenario.ParsePayloadHex(f.PayloadHex)
	}
	return []byte(f.Payload), nil
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
