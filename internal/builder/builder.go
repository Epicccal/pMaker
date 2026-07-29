package builder

import (
	"fmt"
	"time"

	"github.com/gopacket/gopacket"

	"github.com/Epicccal/pMaker/internal/scenario"
)

// OutPacket 是构造好的一个数据包:字节 + 确定性时间戳。
type OutPacket struct {
	Data []byte
	Time time.Time
}

// serOpts 当前统一修正长度并计算 checksum;逐字段覆盖尚未应用。
var serOpts = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

type buildContext struct {
	packetsByName map[string]scenario.Packet
}

// BuildPlanned 把已汇流排序的 PlannedPacket 逐包序列化为字节;
// 时间戳取自每个 PlannedPacket.Time(由 internal/plan 分配)。
func BuildPlanned(planned []scenario.PlannedPacket) ([]OutPacket, error) {
	ctx := buildContext{packetsByName: plannedByName(planned)}
	out := make([]OutPacket, 0, len(planned))
	for i, pp := range planned {
		data, err := serializeStack(ctx, pp.Stack)
		if err != nil {
			name := pp.Name
			if name == "" {
				name = fmt.Sprintf("packet[%d]", i)
			}
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out = append(out, OutPacket{Data: data, Time: pp.Time})
	}
	return out, nil
}

func plannedByName(planned []scenario.PlannedPacket) map[string]scenario.Packet {
	out := map[string]scenario.Packet{}
	for _, pp := range planned {
		if pp.Name != "" {
			out[pp.Name] = pp.Packet
		}
	}
	return out
}

func serializeStack(ctx buildContext, stack []scenario.Layer) ([]byte, error) {
	serLayers := make([]gopacket.SerializableLayer, 0, len(stack))
	var netLayer gopacket.NetworkLayer // 最近的 IP 层,供传输层 checksum 伪首部使用

	for j, l := range stack {
		next := ""
		if j+1 < len(stack) {
			next = stack[j+1].Type
		}

		switch f := l.Fields.(type) {
		case *scenario.EthFields:
			eth, err := buildEth(f, next)
			if err != nil {
				return nil, fmt.Errorf("eth: %w", err)
			}
			serLayers = append(serLayers, eth)
		case *scenario.VLANFields:
			serLayers = append(serLayers, buildVLAN(f, next))
		case *scenario.IPv4Fields:
			ip, err := buildIPv4(f, next)
			if err != nil {
				return nil, fmt.Errorf("ipv4: %w", err)
			}
			netLayer = ip
			serLayers = append(serLayers, ip)
		case *scenario.IPv6Fields:
			ip, err := buildIPv6(f, next)
			if err != nil {
				return nil, fmt.Errorf("ipv6: %w", err)
			}
			netLayer = ip
			serLayers = append(serLayers, ip)
		case *scenario.GREFields:
			serLayers = append(serLayers, buildGRE(next))
		case *scenario.TCPFields:
			t, err := buildTCP(f)
			if err != nil {
				return nil, fmt.Errorf("tcp: %w", err)
			}
			if netLayer != nil {
				_ = t.SetNetworkLayerForChecksum(netLayer)
			}
			serLayers = append(serLayers, t)
		case *scenario.UDPFields:
			u := buildUDP(f)
			if netLayer != nil {
				_ = u.SetNetworkLayerForChecksum(netLayer)
			}
			serLayers = append(serLayers, u)
		case *scenario.ICMPFields:
			icmp, payload, err := buildICMP(ctx, f)
			if err != nil {
				return nil, fmt.Errorf("icmp: %w", err)
			}
			serLayers = append(serLayers, icmp)
			if len(payload) > 0 {
				serLayers = append(serLayers, gopacket.Payload(payload))
			}
		case *scenario.ICMPv6Fields:
			icmp, echo, reserved, payload, err := buildICMPv6(ctx, f)
			if err != nil {
				return nil, fmt.Errorf("icmpv6: %w", err)
			}
			// ICMPv6 校验和依赖 IPv6 伪首部;就近绑定最近的 IP 层(内层 IPv6)。
			if netLayer != nil {
				if err := icmp.SetNetworkLayerForChecksum(netLayer); err != nil {
					return nil, fmt.Errorf("icmpv6: %w", err)
				}
			}
			serLayers = append(serLayers, icmp)
			if echo != nil {
				serLayers = append(serLayers, echo)
			}
			// 错误报文(非 echo)的 4 字节类型相关字段,置于 ICMPv6 头与 quote 之间。
			// 作为独立 Payload 层,gopacket 的 ICMPv6 checksum 会自动将其纳入计算。
			if len(reserved) > 0 {
				serLayers = append(serLayers, gopacket.Payload(reserved))
			}
			if len(payload) > 0 {
				serLayers = append(serLayers, gopacket.Payload(payload))
			}
		case *scenario.PayloadFields:
			b, err := payloadBytes(f)
			if err != nil {
				return nil, fmt.Errorf("payload: %w", err)
			}
			serLayers = append(serLayers, gopacket.Payload(b))
		case scenario.PayloadHex:
			b, err := scenario.ParsePayloadHex(string(f))
			if err != nil {
				return nil, fmt.Errorf("payload_hex: %w", err)
			}
			serLayers = append(serLayers, gopacket.Payload(b))
		case *scenario.DNSFields:
			d, err := buildDNS(f)
			if err != nil {
				return nil, fmt.Errorf("dns: %w", err)
			}
			serLayers = append(serLayers, d)
		case *scenario.HTTPReqFields:
			serLayers = append(serLayers, gopacket.Payload(serializeHTTPReq(f)))
		case *scenario.HTTPRespFields:
			serLayers = append(serLayers, gopacket.Payload(serializeHTTPResp(f)))
		case *scenario.FTPRequestFields:
			serLayers = append(serLayers, gopacket.Payload(serializeFTPReq(f)))
		case *scenario.FTPResponseFields:
			serLayers = append(serLayers, gopacket.Payload(serializeFTPResp(f)))
		case *scenario.TelnetFields:
			b, err := serializeTelnet(f)
			if err != nil {
				return nil, fmt.Errorf("telnet: %w", err)
			}
			serLayers = append(serLayers, gopacket.Payload(b))
		default:
			return nil, fmt.Errorf("不支持的层类型 %q", l.Type)
		}
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serOpts, serLayers...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
