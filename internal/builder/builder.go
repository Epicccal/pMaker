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
	// layerOpts / lenFill 与 serLayers 一一对应:每层各自的 SerializeOptions 与长度覆盖标志。
	// 默认 = defaultSerOpts(自动修正长度 + 计算 checksum);显式覆盖时拷贝一份按需关掉。
	// 索引必须跟着 serLayers 走:ICMPv6 一个 scenario 层会 append 出 icmp/echo/reserved/payload
	// 多项,每项都要配对,故统一走 add,不在 switch 外零散 append。
	layerOpts := make([]gopacket.SerializeOptions, 0, len(stack))
	// lenFill 记录每层哪些长度字段被显式覆盖(非 nil=原样落值,nil=未覆盖、反向循环按公式补值)。
	// 覆盖与否靠 scenario 字段指针区分(两态:写即覆盖、不写即自动),不能对结构体做零值检测
	// —— 显式 0 与未覆盖在结构体上都是 0。
	lenFill := make([]lengthOverrideInfo, 0, len(stack))
	add := func(l gopacket.SerializableLayer, csum *scenario.Hex, info lengthOverrideInfo) {
		o := defaultSerOpts
		if csum != nil {
			o.ComputeChecksums = false
		}
		if info.any() {
			o.FixLengths = false
		}
		serLayers = append(serLayers, l)
		layerOpts = append(layerOpts, o)
		lenFill = append(lenFill, info)
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
			add(eth, nil, lengthOverrideInfo{})
		case *scenario.VLANFields:
			vlan, err := buildVLAN(f, next)
			if err != nil {
				return nil, fmt.Errorf("vlan: %w", err)
			}
			add(vlan, nil, lengthOverrideInfo{})
		case *scenario.IPv4Fields:
			ip, err := buildIPv4(f, next)
			if err != nil {
				return nil, fmt.Errorf("ipv4: %w", err)
			}
			netLayer = ip
			add(ip, f.Checksum, lengthOverrideInfo{ipv4Length: f.Length, ipv4IHL: f.IHL})
		case *scenario.IPv6Fields:
			ip, err := buildIPv6(f, next)
			if err != nil {
				return nil, fmt.Errorf("ipv6: %w", err)
			}
			netLayer = ip
			add(ip, nil, lengthOverrideInfo{ipv6PayloadLength: f.PayloadLength})
		case *scenario.GREFields:
			gre, err := buildGRE(next)
			if err != nil {
				return nil, fmt.Errorf("gre: %w", err)
			}
			add(gre, nil, lengthOverrideInfo{})
		case *scenario.TCPFields:
			t, err := buildTCP(f)
			if err != nil {
				return nil, fmt.Errorf("tcp: %w", err)
			}
			if netLayer != nil {
				_ = t.SetNetworkLayerForChecksum(netLayer)
			}
			add(t, f.Checksum, lengthOverrideInfo{tcpDataOffset: f.DataOffset})
		case *scenario.UDPFields:
			u := buildUDP(f)
			if netLayer != nil {
				_ = u.SetNetworkLayerForChecksum(netLayer)
			}
			add(u, f.Checksum, lengthOverrideInfo{udpLength: f.Length})
		case *scenario.ICMPFields:
			icmp, payload, err := buildICMP(ctx, f)
			if err != nil {
				return nil, fmt.Errorf("icmp: %w", err)
			}
			add(icmp, f.Checksum, lengthOverrideInfo{})
			if len(payload) > 0 {
				add(gopacket.Payload(payload), nil, lengthOverrideInfo{})
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
			add(icmp, f.Checksum, lengthOverrideInfo{})
			if echo != nil {
				add(echo, nil, lengthOverrideInfo{})
			}
			// 错误报文(非 echo)的 4 字节类型相关字段,置于 ICMPv6 头与 quote 之间。
			// 作为独立 Payload 层,gopacket 的 ICMPv6 checksum 会自动将其纳入计算。
			if len(reserved) > 0 {
				add(gopacket.Payload(reserved), nil, lengthOverrideInfo{})
			}
			if len(payload) > 0 {
				add(gopacket.Payload(payload), nil, lengthOverrideInfo{})
			}
		case *scenario.PayloadFields:
			b, err := payloadBytes(f)
			if err != nil {
				return nil, fmt.Errorf("payload: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case scenario.PayloadHex:
			b, err := scenario.ParsePayloadHex(string(f))
			if err != nil {
				return nil, fmt.Errorf("payload_hex: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case *scenario.DNSFields:
			d, err := buildDNS(f)
			if err != nil {
				return nil, fmt.Errorf("dns: %w", err)
			}
			add(d, nil, lengthOverrideInfo{})
		case *scenario.HTTPReqFields:
			b, err := serializeHTTPReq(f)
			if err != nil {
				return nil, fmt.Errorf("http_request: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case *scenario.HTTPRespFields:
			b, err := serializeHTTPResp(f)
			if err != nil {
				return nil, fmt.Errorf("http_response: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case *scenario.FTPRequestFields:
			add(gopacket.Payload(serializeFTPReq(f)), nil, lengthOverrideInfo{})
		case *scenario.FTPResponseFields:
			add(gopacket.Payload(serializeFTPResp(f)), nil, lengthOverrideInfo{})
		case *scenario.TelnetFields:
			b, err := serializeTelnet(f)
			if err != nil {
				return nil, fmt.Errorf("telnet: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case *scenario.SMTPRequestFields:
			add(gopacket.Payload(serializeSMTPReq(f)), nil, lengthOverrideInfo{})
		case *scenario.SMTPResponseFields:
			add(gopacket.Payload(serializeSMTPResp(f)), nil, lengthOverrideInfo{})
		case *scenario.POP3RequestFields:
			add(gopacket.Payload(serializePOP3Req(f)), nil, lengthOverrideInfo{})
		case *scenario.POP3ResponseFields:
			b, err := serializePOP3Resp(f)
			if err != nil {
				return nil, fmt.Errorf("pop3_response: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case *scenario.IMAPRequestFields:
			b, err := serializeIMAPReq(f)
			if err != nil {
				return nil, fmt.Errorf("imap_request: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case *scenario.IMAPResponseFields:
			b, err := serializeIMAPResp(f)
			if err != nil {
				return nil, fmt.Errorf("imap_response: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		case *scenario.EMLDataFields:
			b, err := serializeEMLDataFramed(f)
			if err != nil {
				return nil, fmt.Errorf("eml_data: %w", err)
			}
			add(gopacket.Payload(b), nil, lengthOverrideInfo{})
		default:
			return nil, fmt.Errorf("不支持的层类型 %q", l.Type)
		}
	}

	// 自写逐层序列化循环(等价于 gopacket.SerializeLayers,但允许每层用不同 opts)。
	// 反向(从最内层到最外层)依次 PrependBytes,与 SerializeLayers 行为一致。
	buf := gopacket.NewSerializeBuffer()
	if err := buf.Clear(); err != nil {
		return nil, fmt.Errorf("清空序列化缓冲区: %w", err)
	}
	for i := len(serLayers) - 1; i >= 0; i-- {
		// SerializeTo 之前补值:此时 buf.Bytes() 是该层 payload(尚未 prepend 本层头),
		// 与 gopacket 内部取值时机一致。只对有覆盖的层(info.any())补未覆盖字段为公式值;
		// 覆盖字段(含显式 0)原样落值,不碰。
		if err := fillLengths(serLayers[i], lenFill[i], buf); err != nil {
			return nil, fmt.Errorf("序列化层 %d(%s): %w", i, serLayers[i].LayerType(), err)
		}
		if err := serLayers[i].SerializeTo(buf, layerOpts[i]); err != nil {
			// 索引 i 是 serLayers 的位置(由外到内),与 stack 非一一对应
			// (ICMPv6 一个 scenario 层会展开多项),故用 gopacket LayerType 定位。
			return nil, fmt.Errorf("序列化层 %d(%s): %w", i, serLayers[i].LayerType(), err)
		}
		buf.PushLayer(serLayers[i].LayerType())
	}
	return buf.Bytes(), nil
}
