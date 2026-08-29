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

// defaultSerOpts 是各层 SerializeOptions 的模板:统一修正长度并计算 checksum。
// per-layer 覆盖时拷贝一份再按需关掉 ComputeChecksums(见 serializeStack 的 add 闭包)。
var defaultSerOpts = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

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
	// layerOpts 与 serLayers 一一对应:每层各自的 SerializeOptions。
	// 默认 = defaultSerOpts;某层显式覆盖 checksum 时,拷贝一份并关掉其 ComputeChecksums,
	// 让结构体上的 Checksum 值原样上 wire(三态语义:nil=自动计算,非 nil=原样落值)。
	layerOpts := make([]gopacket.SerializeOptions, 0, len(stack))
	// add 把一个序列化层及其 opts 配对追加。csum 非 nil 表示该层显式覆盖了 checksum,
	// 关掉自动计算;传 nil 则用默认 opts(自动计算 + 修正长度)。
	// 索引必须跟着 serLayers 走:ICMPv6 一个 scenario 层会 append 出 icmp/echo/reserved/payload
	// 多项,每项都要配对 opts,故统一走 add,不在 switch 外零散 append。
	add := func(l gopacket.SerializableLayer, csum *scenario.Hex) {
		o := defaultSerOpts
		if csum != nil {
			o.ComputeChecksums = false
		}
		serLayers = append(serLayers, l)
		layerOpts = append(layerOpts, o)
	}
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
			add(eth, nil)
		case *scenario.VLANFields:
			add(buildVLAN(f, next), nil)
		case *scenario.IPv4Fields:
			ip, err := buildIPv4(f, next)
			if err != nil {
				return nil, fmt.Errorf("ipv4: %w", err)
			}
			netLayer = ip
			add(ip, f.Checksum)
		case *scenario.IPv6Fields:
			ip, err := buildIPv6(f, next)
			if err != nil {
				return nil, fmt.Errorf("ipv6: %w", err)
			}
			netLayer = ip
			add(ip, nil)
		case *scenario.GREFields:
			add(buildGRE(next), nil)
		case *scenario.TCPFields:
			t, err := buildTCP(f)
			if err != nil {
				return nil, fmt.Errorf("tcp: %w", err)
			}
			if netLayer != nil {
				_ = t.SetNetworkLayerForChecksum(netLayer)
			}
			add(t, f.Checksum)
		case *scenario.UDPFields:
			u := buildUDP(f)
			if netLayer != nil {
				_ = u.SetNetworkLayerForChecksum(netLayer)
			}
			add(u, f.Checksum)
		case *scenario.ICMPFields:
			icmp, payload, err := buildICMP(ctx, f)
			if err != nil {
				return nil, fmt.Errorf("icmp: %w", err)
			}
			add(icmp, f.Checksum)
			if len(payload) > 0 {
				add(gopacket.Payload(payload), nil)
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
			add(icmp, f.Checksum)
			if echo != nil {
				add(echo, nil)
			}
			// 错误报文(非 echo)的 4 字节类型相关字段,置于 ICMPv6 头与 quote 之间。
			// 作为独立 Payload 层,gopacket 的 ICMPv6 checksum 会自动将其纳入计算。
			if len(reserved) > 0 {
				add(gopacket.Payload(reserved), nil)
			}
			if len(payload) > 0 {
				add(gopacket.Payload(payload), nil)
			}
		case *scenario.PayloadFields:
			b, err := payloadBytes(f)
			if err != nil {
				return nil, fmt.Errorf("payload: %w", err)
			}
			add(gopacket.Payload(b), nil)
		case scenario.PayloadHex:
			b, err := scenario.ParsePayloadHex(string(f))
			if err != nil {
				return nil, fmt.Errorf("payload_hex: %w", err)
			}
			add(gopacket.Payload(b), nil)
		case *scenario.DNSFields:
			d, err := buildDNS(f)
			if err != nil {
				return nil, fmt.Errorf("dns: %w", err)
			}
			add(d, nil)
		case *scenario.HTTPReqFields:
			b, err := serializeHTTPReq(f)
			if err != nil {
				return nil, fmt.Errorf("http_request: %w", err)
			}
			add(gopacket.Payload(b), nil)
		case *scenario.HTTPRespFields:
			b, err := serializeHTTPResp(f)
			if err != nil {
				return nil, fmt.Errorf("http_response: %w", err)
			}
			add(gopacket.Payload(b), nil)
		case *scenario.FTPRequestFields:
			add(gopacket.Payload(serializeFTPReq(f)), nil)
		case *scenario.FTPResponseFields:
			add(gopacket.Payload(serializeFTPResp(f)), nil)
		case *scenario.TelnetFields:
			b, err := serializeTelnet(f)
			if err != nil {
				return nil, fmt.Errorf("telnet: %w", err)
			}
			add(gopacket.Payload(b), nil)
		case *scenario.SMTPRequestFields:
			add(gopacket.Payload(serializeSMTPReq(f)), nil)
		case *scenario.SMTPResponseFields:
			add(gopacket.Payload(serializeSMTPResp(f)), nil)
		case *scenario.POP3RequestFields:
			add(gopacket.Payload(serializePOP3Req(f)), nil)
		case *scenario.POP3ResponseFields:
			b, err := serializePOP3Resp(f)
			if err != nil {
				return nil, fmt.Errorf("pop3_response: %w", err)
			}
			add(gopacket.Payload(b), nil)
		case *scenario.EMLDataFields:
			b, err := serializeEMLDataFramed(f)
			if err != nil {
				return nil, fmt.Errorf("eml_data: %w", err)
			}
			add(gopacket.Payload(b), nil)
		default:
			return nil, fmt.Errorf("不支持的层类型 %q", l.Type)
		}
	}

	// 自写逐层序列化循环(等价于 gopacket.SerializeLayers,但允许每层用不同 opts)。
	// 反向(从最内层到最外层)依次 PrependBytes,与 SerializeLayers 行为一致。
	buf := gopacket.NewSerializeBuffer()
	if err := buf.Clear(); err != nil {
		return nil, err
	}
	for i := len(serLayers) - 1; i >= 0; i-- {
		if err := serLayers[i].SerializeTo(buf, layerOpts[i]); err != nil {
			return nil, err
		}
		buf.PushLayer(serLayers[i].LayerType())
	}
	return buf.Bytes(), nil
}
